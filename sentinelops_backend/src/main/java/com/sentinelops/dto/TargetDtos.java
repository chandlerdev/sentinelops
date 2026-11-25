package com.sentinelops.dto;

import com.sentinelops.entity.*;
import com.sentinelops.service.VerificationService;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.time.Instant;
import java.util.List;

public final class TargetDtos {
    private TargetDtos() {}

    public record TargetRequest(
            @NotBlank @Size(max = 255) String value,
            @Size(max = 512) String baseUrl,
            @Size(max = 255) String label,
            Technology technology,
            boolean lab,
            boolean sharedHostException) {}

    /** "status" is the effective state: VERIFIED, EXPIRED (was verified, now lapsed), UNVERIFIED, or LAB. */
    public record TargetView(String id, String engagementId, TargetKind kind, String value, String baseUrl,
                             String label, Technology technology, boolean lab, boolean sharedHostException,
                             String status, Instant verifiedAt, Instant verificationExpiresAt, Instant createdAt,
                             String openApiUrl) {
        public static TargetView from(Target t) {
            Instant now = Instant.now();
            String status;
            if (t.isLab()) status = "LAB";
            else if (t.isVerifiedAt(now)) status = "VERIFIED";
            else if (t.getVerificationStatus() == TargetStatus.VERIFIED) status = "EXPIRED";
            else status = "UNVERIFIED";
            return new TargetView(t.getId(), t.getEngagementId(), t.getKind(), t.getValue(), t.getBaseUrl(),
                    t.getLabel(), t.getTechnology(), t.isLab(), t.isSharedHostException(), status, t.getVerifiedAt(),
                    t.getVerificationExpiresAt(), t.getCreatedAt(), t.getOpenApiUrl());
        }
    }

    public record StartVerificationRequest(@NotNull VerificationMethod method) {}

    public record ManualApprovalRequest(
            @NotBlank @Size(max = 255) String approverName,
            @NotBlank @Size(max = 255) String approverContact,
            @NotBlank @Size(max = 255) String networkAckBy,
            @NotBlank @Size(max = 512) String evidenceRef,
            @Size(max = 500) String notes) {}

    public record VerificationView(String id, String targetId, VerificationMethod method, ChallengeStatus status,
                                   Instant expiresAt, Instant verifiedAt, Instant lastCheckedAt, String detail,
                                   String approverName, String networkAckBy, String evidenceRef,
                                   String recordName, String recordValue, String fileUrl, String fileContent) {
        public static VerificationView from(TargetVerification v) {
            return new VerificationView(v.getId(), v.getTargetId(), v.getMethod(), v.getStatus(), v.getExpiresAt(),
                    v.getVerifiedAt(), v.getLastCheckedAt(), v.getDetail(), v.getApproverName(),
                    v.getNetworkAckBy(), v.getEvidenceRef(), null, null, null, null);
        }

        public static VerificationView from(VerificationService.ChallengeView c) {
            TargetVerification v = c.verification();
            VerificationService.Instructions i = c.instructions();
            return new VerificationView(v.getId(), v.getTargetId(), v.getMethod(), v.getStatus(), v.getExpiresAt(),
                    v.getVerifiedAt(), v.getLastCheckedAt(), v.getDetail(), v.getApproverName(),
                    v.getNetworkAckBy(), v.getEvidenceRef(),
                    i.recordName(), i.recordValue(), i.fileUrl(), i.fileContent());
        }
    }

    public record GateCheckRequest(@NotNull ScanCategory category, @NotNull ScanMode mode) {}

    public record GateCheckView(boolean allowed, String reason, List<String> resolvedAddresses, ScanMode effectiveMode) {}
}
