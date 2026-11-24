package com.sentinelops.service.logic;

import com.sentinelops.config.AppProperties;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.HexFormat;

/** Builds the multipart body itself (the JDK client has no built-in helper); no redirects, a short timeout. */
@Component
public class JdkUploadHttpClient implements UploadHttpClient {

    private static final int MAX_BYTES = 8192;
    private static final SecureRandom RANDOM = new SecureRandom();
    private final HttpClient client;
    private final Duration timeout;

    public JdkUploadHttpClient(AppProperties props) {
        this.timeout = Duration.ofSeconds(props.getVerification().getHttpTimeoutSeconds());
        this.client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(timeout)
                .build();
    }

    @Override
    public Result uploadMultipart(String url, String fieldName, String filename, byte[] content, String contentType,
                                  String headerName, String headerValue) throws Exception {
        byte[] boundaryBytes = new byte[16];
        RANDOM.nextBytes(boundaryBytes);
        String boundary = "SentinelOps" + HexFormat.of().formatHex(boundaryBytes);

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(("--" + boundary + "\r\n").getBytes(StandardCharsets.UTF_8));
        body.write(("Content-Disposition: form-data; name=\"" + fieldName + "\"; filename=\"" + filename + "\"\r\n")
                .getBytes(StandardCharsets.UTF_8));
        body.write(("Content-Type: " + contentType + "\r\n\r\n").getBytes(StandardCharsets.UTF_8));
        body.write(content);
        body.write(("\r\n--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8));

        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url))
                .timeout(timeout)
                .header("User-Agent", "SentinelOps-LogicProbe/1.0")
                .header("Content-Type", "multipart/form-data; boundary=" + boundary);
        if (headerName != null && headerValue != null) b.header(headerName, headerValue);
        b.POST(HttpRequest.BodyPublishers.ofByteArray(body.toByteArray()));
        return send(b);
    }

    @Override
    public Result get(String url, String headerName, String headerValue) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url))
                .timeout(timeout)
                .header("User-Agent", "SentinelOps-LogicProbe/1.0")
                .GET();
        if (headerName != null && headerValue != null) b.header(headerName, headerValue);
        return send(b);
    }

    private Result send(HttpRequest.Builder b) throws Exception {
        HttpResponse<byte[]> res = client.send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
        byte[] raw = res.body() == null ? new byte[0] : res.body();
        int len = Math.min(raw.length, MAX_BYTES);
        return new Result(res.statusCode(), new String(raw, 0, len, StandardCharsets.UTF_8));
    }
}
