package com.sentinelops.controller;

import com.sentinelops.service.ReportService;
import com.sentinelops.util.CurrentUser;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/engagements/{id}")
public class ReportController {

    private final ReportService reports;

    public ReportController(ReportService reports) {
        this.reports = reports;
    }

    /** PDF report. A CLIENT always gets confirmed findings only; staff may add unconfirmed ones with includeCandidates=true. */
    @GetMapping("/report")
    public ResponseEntity<byte[]> report(@PathVariable String id,
                                         @RequestParam(defaultValue = "false") boolean includeCandidates) {
        var r = reports.generate(id, includeCandidates, CurrentUser.email());
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_PDF)
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.attachment().filename(r.fileName()).build().toString())
                .header("X-Report-SHA256", r.sha256())
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .body(r.pdf());
    }
}
