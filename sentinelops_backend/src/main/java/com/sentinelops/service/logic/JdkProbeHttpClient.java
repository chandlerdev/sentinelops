package com.sentinelops.service.logic;

import com.sentinelops.config.AppProperties;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/** HTTP GET/POST with no body, matching the other logic-testing clients: no redirects, a short timeout. */
@Component
public class JdkProbeHttpClient implements ProbeHttpClient {

    private static final int MAX_BYTES = 8192;
    private final HttpClient client;
    private final Duration timeout;

    public JdkProbeHttpClient(AppProperties props) {
        this.timeout = Duration.ofSeconds(props.getVerification().getHttpTimeoutSeconds());
        this.client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(timeout)
                .build();
    }

    @Override
    public Result callWithBody(String method, String url, String headerName, String headerValue) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url))
                .timeout(timeout)
                .header("User-Agent", "SentinelOps-LogicProbe/1.0");
        if (headerName != null && headerValue != null) b.header(headerName, headerValue);
        b.method("POST".equalsIgnoreCase(method) ? "POST" : "GET", HttpRequest.BodyPublishers.noBody());
        HttpResponse<byte[]> res = client.send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
        int len = res.body() == null ? 0 : Math.min(res.body().length, MAX_BYTES);
        return new Result(res.statusCode(), len);
    }
}
