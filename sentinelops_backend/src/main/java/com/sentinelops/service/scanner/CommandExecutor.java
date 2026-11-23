package com.sentinelops.service.scanner;

import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/** Runs one external program. The argument list is passed as-is to the OS; no shell is ever involved. */
public interface CommandExecutor {

    record Result(int exitCode, boolean timedOut, String outputTail) {}

    Result exec(List<String> argv, Duration timeout) throws IOException;

    /**
     * Same, with extra environment variables for the child process only. Used for secrets so they never appear
     * in a command line that other users of the server could read with ps.
     */
    default Result exec(List<String> argv, Map<String, String> env, Duration timeout) throws IOException {
        return exec(argv, timeout);
    }
}
