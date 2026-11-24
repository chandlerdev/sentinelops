package com.sentinelops.service.logic;

import com.sentinelops.config.AppProperties;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/** HTTP POST/PUT with a JSON body, matching the other logic-testing clients: no redirects, a short timeout. */
@Component
public class JdkBusinessHttpClient implements BusinessHttpClient {

    private final HttpClient client;
    private final Duration timeout;

    public JdkBusinessHttpClient(AppProperties props) {
        this.timeout = Duration.ofSeconds(props.getVerification().getHttpTimeoutSeconds());
        this.client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(timeout)
                .build();
    }

    @Override
    public Result send(String method, String url, String jsonBody, String headerName, String headerValue) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url))
                .timeout(timeout)
                .header("User-Agent", "SentinelOps-LogicProbe/1.0")
                .header("Content-Type", "application/json");
        if (headerName != null && headerValue != null) b.header(headerName, headerValue);
        b.method("PUT".equalsIgnoreCase(method) ? "PUT" : "POST",
                HttpRequest.BodyPublishers.ofString(jsonBody, StandardCharsets.UTF_8));
        HttpResponse<Void> res = client.send(b.build(), HttpResponse.BodyHandlers.discarding());
        return new Result(res.statusCode());
    }
}
