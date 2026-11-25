package com.sentinelops.service.scanner;

import com.sentinelops.config.AppProperties;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * The only place that launches a scanner. It builds ONE fixed shape of command:
 * <pre>docker run --rm --name N [--network X] --cap-drop ALL --security-opt no-new-privileges ... IMAGE command...</pre>
 * as an argument list (no shell, no string concatenation of untrusted text). Callers hand it validated values only
 * ({@link ScanContext}); it checks again that nothing could be read as an option.
 * <p>
 * Remember: access to the Docker socket is equivalent to root on the host, so this class must stay small and boring.
 */
@Component
public class DockerRunner {

    private static final Pattern NAME = Pattern.compile("^sentinelops-[a-z][a-z-]{1,14}-[0-9a-f-]{36}$");
    private static final Pattern NETWORK = Pattern.compile("^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$");
    private static final Pattern IMAGE = Pattern.compile("^[a-z0-9][a-z0-9._/-]{0,127}(:[A-Za-z0-9._-]{1,128})?(@sha256:[0-9a-f]{64})?$");
    private static final Pattern IPV4 = Pattern.compile("^[0-9]{1,3}(\\.[0-9]{1,3}){3}$");
    private static final Pattern ENV_NAME = Pattern.compile("^[A-Z][A-Z0-9_]{0,40}$");
    private static final Pattern HOST =Pattern.compile("^[a-z0-9][a-z0-9.-]{0,252}$");

    /** A second, read-only bind mount besides the work dir (e.g. pre-downloaded nuclei templates). */
    public record ExtraMount(String hostPath, String containerPath) {}

    public record RunSpec(String containerName, String image, String network, String host, List<String> pinnedIpv4,
                          Path hostOutDir, String containerOutDir, List<String> command, Duration timeout,
                          Map<String, String> env, List<ExtraMount> extraMounts) {
        public RunSpec(String containerName, String image, String network, String host, List<String> pinnedIpv4,
                       Path hostOutDir, String containerOutDir, List<String> command, Duration timeout) {
            this(containerName, image, network, host, pinnedIpv4, hostOutDir, containerOutDir, command, timeout, Map.of(), List.of());
        }
        public RunSpec(String containerName, String image, String network, String host, List<String> pinnedIpv4,
                       Path hostOutDir, String containerOutDir, List<String> command, Duration timeout,
                       Map<String, String> env) {
            this(containerName, image, network, host, pinnedIpv4, hostOutDir, containerOutDir, command, timeout, env, List.of());
        }
    }

    private final CommandExecutor executor;
    private final AppProperties props;

    public DockerRunner(CommandExecutor executor, AppProperties props) {
        this.executor = executor;
        this.props = props;
    }

    public static String containerName(String toolId, String runId) {
        return "sentinelops-" + toolId + "-" + runId;
    }

    /** Pure function: the exact argv that will be executed. */
    public List<String> buildCommand(RunSpec s) {
        AppProperties.Engine e = props.getScan().getEngine();
        require(NAME.matcher(s.containerName()).matches(), "container name");
        require(IMAGE.matcher(s.image()).matches(), "image");
        require(s.network() == null || s.network().isEmpty() || NETWORK.matcher(s.network()).matches(), "network");
        require(!s.hostOutDir().toString().contains(",") && !s.hostOutDir().toString().contains("\n"), "work dir");
        require(s.containerOutDir().startsWith("/") && !s.containerOutDir().contains(","), "container dir");
        require(e.getCpus().matches("^[0-9]+(\\.[0-9]+)?$") && e.getMemory().matches("^[0-9]+[kmg]$"), "resource limits");

        List<String> argv = new ArrayList<>();
        argv.add(e.getDockerBinary());
        argv.addAll(List.of("run", "--rm", "--name", s.containerName()));
        if (s.network() != null && !s.network().isEmpty()) {
            argv.add("--network");
            argv.add(s.network());
        }
        argv.addAll(List.of("--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--pids-limit", "512", "--memory", e.getMemory(), "--cpus", e.getCpus()));
        if (s.host() != null && s.pinnedIpv4() != null) {
            for (String ip : s.pinnedIpv4()) {
                require(HOST.matcher(s.host()).matches() && IPV4.matcher(ip).matches(), "pinned address");
                argv.add("--add-host");
                argv.add(s.host() + ":" + ip);
            }
        }
        // Secrets: "-e NAME" without a value makes Docker read it from OUR environment, so it is not in any command line.
        if (s.env() != null) {
            for (String name : s.env().keySet()) {
                require(ENV_NAME.matcher(name).matches(), "environment name");
                argv.add("-e");
                argv.add(name);
            }
        }
        argv.add("--mount");
        argv.add("type=bind,source=" + s.hostOutDir().toAbsolutePath() + ",target=" + s.containerOutDir());
        if (s.extraMounts() != null) {
            for (ExtraMount m : s.extraMounts()) {
                require(m.hostPath() != null && !m.hostPath().isBlank()
                        && !m.hostPath().contains(",") && !m.hostPath().contains("\n"), "extra mount source");
                require(m.containerPath() != null && m.containerPath().startsWith("/") && !m.containerPath().contains(","),
                        "extra mount target");
                argv.add("--mount");
                argv.add("type=bind,source=" + Path.of(m.hostPath()).toAbsolutePath() + ",target=" + m.containerPath() + ",readonly");
            }
        }
        argv.add(s.image());
        for (String a : s.command()) {
            require(a != null && a.indexOf('\0') < 0 && a.indexOf('\n') < 0 && a.indexOf('\r') < 0, "argument");
            argv.add(a);
        }
        return argv;
    }

    public CommandExecutor.Result run(RunSpec spec) throws IOException {
        List<String> argv = buildCommand(spec);
        CommandExecutor.Result r = executor.exec(argv, spec.env() == null ? Map.of() : spec.env(), spec.timeout());
        if (r.timedOut()) kill(spec.containerName());
        return r;
    }

    /** Force-removes a scanner container (stop request, timeout, restart recovery). Safe if it does not exist. */
    public void kill(String containerName) {
        if (!NAME.matcher(containerName).matches()) return;
        try {
            executor.exec(List.of(props.getScan().getEngine().getDockerBinary(), "rm", "-f", containerName), Duration.ofSeconds(30));
        } catch (IOException ignored) {
            // best effort
        }
    }

    private static void require(boolean ok, String what) {
        if (!ok) throw new IllegalArgumentException("Docker run refused: invalid " + what);
    }
}
