package com.sentinelops.service.scanner;

import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/** Real executor: ProcessBuilder with an argument list, stdout+stderr merged and kept only as a short tail. */
@Component
public class ProcessCommandExecutor implements CommandExecutor {

    private static final int TAIL_BYTES = 4096;

    @Override
    public Result exec(List<String> argv, Duration timeout) throws IOException {
        return exec(argv, Map.of(), timeout);
    }

    @Override
    public Result exec(List<String> argv, Map<String, String> env, Duration timeout) throws IOException {
        ProcessBuilder pb = new ProcessBuilder(argv).redirectErrorStream(true);
        pb.environment().putAll(env);
        Process p = pb.start();
        TailReader reader = new TailReader(p.getInputStream());
        Thread t = new Thread(reader, "scan-output-reader");
        t.setDaemon(true);
        t.start();
        try {
            boolean done = p.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS);
            if (!done) {
                p.destroyForcibly();
                p.waitFor(5, TimeUnit.SECONDS);
                t.join(1000);
                return new Result(-1, true, reader.tail());
            }
            t.join(2000);
            return new Result(p.exitValue(), false, reader.tail());
        } catch (InterruptedException ex) {
            p.destroyForcibly();
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while waiting for the command", ex);
        }
    }

    private static final class TailReader implements Runnable {
        private final InputStream in;
        private final byte[] buf = new byte[TAIL_BYTES];
        private int len = 0;

        TailReader(InputStream in) { this.in = in; }

        @Override
        public void run() {
            byte[] chunk = new byte[2048];
            try {
                int n;
                while ((n = in.read(chunk)) > 0) {
                    synchronized (this) {
                        if (n >= TAIL_BYTES) {
                            System.arraycopy(chunk, n - TAIL_BYTES, buf, 0, TAIL_BYTES);
                            len = TAIL_BYTES;
                        } else {
                            int keep = Math.min(len, TAIL_BYTES - n);
                            System.arraycopy(buf, len - keep, buf, 0, keep);
                            System.arraycopy(chunk, 0, buf, keep, n);
                            len = keep + n;
                        }
                    }
                }
            } catch (IOException ignored) {
                // process ended
            }
        }

        synchronized String tail() {
            return new String(buf, 0, len, StandardCharsets.UTF_8);
        }
    }
}
