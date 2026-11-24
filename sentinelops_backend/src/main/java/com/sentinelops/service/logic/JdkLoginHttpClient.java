package com.sentinelops.service.logic;

import com.sentinelops.config.AppProperties;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * HTTP POST with hard limits, matching {@code JdkHttpTokenFetcher}: no redirects (they could point at
 * internal addresses), a short timeout, and at most 4 KiB of response body.
 */
@Component
public class JdkLoginHttpClient implements LoginHttpClient {

    private static final int MAX_BYTES = 4096;
    private final HttpClient client;
    private final Duration timeout;

    public JdkLoginHttpClient(AppProperties props) {
        this.timeout = Duration.ofSeconds(props.getVerification().getHttpTimeoutSeconds());
        this.client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(timeout)
                .build();
    }

    @Override
    public Response post(String url, String jsonBody) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                .timeout(timeout)
                .header("User-Agent", "SentinelOps-LoginProbe/1.0")
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody, StandardCharsets.UTF_8))
                .build();
        HttpResponse<InputStream> res = client.send(req, HttpResponse.BodyHandlers.ofInputStream());
        try (InputStream in = res.body()) {
            byte[] buf = in.readNBytes(MAX_BYTES);
            return new Response(res.statusCode(), res.headers().map(), new String(buf, StandardCharsets.UTF_8));
        }
    }
}
