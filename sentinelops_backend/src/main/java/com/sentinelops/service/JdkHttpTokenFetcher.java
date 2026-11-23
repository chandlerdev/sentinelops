package com.sentinelops.service;

import com.sentinelops.config.AppProperties;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Optional;

/**
 * HTTP fetch with hard limits: no redirects (they could point at internal addresses), short timeouts,
 * and at most 1 KiB of body. The caller must validate the host's addresses BEFORE calling this.
 */
@Component
public class JdkHttpTokenFetcher implements HttpTokenFetcher {

    private static final int MAX_BYTES = 1024;
    private final HttpClient client;
    private final Duration timeout;

    public JdkHttpTokenFetcher(AppProperties props) {
        this.timeout = Duration.ofSeconds(props.getVerification().getHttpTimeoutSeconds());
        this.client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(timeout)
                .build();
    }

    @Override
    public Optional<String> fetch(String url) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                .timeout(timeout)
                .header("User-Agent", "SentinelOps-Verifier/1.0")
                .GET().build();
        HttpResponse<InputStream> res = client.send(req, HttpResponse.BodyHandlers.ofInputStream());
        try (InputStream in = res.body()) {
            if (res.statusCode() != 200) return Optional.empty();
            byte[] buf = in.readNBytes(MAX_BYTES);
            return Optional.of(new String(buf, StandardCharsets.UTF_8).trim());
        }
    }
}
