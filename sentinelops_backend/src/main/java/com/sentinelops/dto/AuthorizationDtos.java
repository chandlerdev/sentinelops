package com.sentinelops.dto;

import com.sentinelops.entity.AuthStatus;
import com.sentinelops.entity.Authorization;
import com.sentinelops.entity.ScanCategory;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.time.Instant;
import java.util.List;
import java.util.Set;

public final class AuthorizationDtos {
    private AuthorizationDtos() {}

    public record AuthorizationRequest(
            @NotBlank @Size(max = 255) String title,
            @NotBlank @Size(max = 255) String approverName,
            @NotBlank @Size(max = 255) String approverContact,
            @NotBlank @Size(max = 255) String emergencyContact,
            @NotEmpty Set<ScanCategory> permittedMethods,
            List<@NotBlank String> excludedAssets,
            @NotNull Instant windowStart,
            @NotNull Instant windowEnd,
            boolean allowActive,
            @NotBlank @Size(max = 255) String evidenceRef,
            @NotEmpty Set<@NotBlank String> targetIds,
            boolean allowAuthenticated) {}

    public record DecisionRequest(@Size(max = 1000) String note) {}

    public record AuthorizationView(String id, String engagementId, String title, AuthStatus status,
                                    String requestedBy, String approverName, String approverContact,
                                    String emergencyContact, Set<ScanCategory> permittedMethods,
                                    List<String> excludedAssets, Instant windowStart, Instant windowEnd,
                                    boolean allowActive, String evidenceRef, Set<String> targetIds,
                                    String signedBy, Instant signedAt, String approvedBy, String decisionNote,
                                    Instant createdAt, boolean allowAuthenticated) {
        public static AuthorizationView from(Authorization a) {
            return new AuthorizationView(a.getId(), a.getEngagementId(), a.getTitle(), a.getStatus(),
                    a.getRequestedBy(), a.getApproverName(), a.getApproverContact(), a.getEmergencyContact(),
                    a.getPermittedMethodSet(), a.getExcludedAssetList(), a.getWindowStart(), a.getWindowEnd(),
                    a.isAllowActive(), a.getRoeReference(), Set.copyOf(a.getTargetIds()), a.getSignedBy(),
                    a.getSignedAt(), a.getApprovedBy(), a.getDecisionNote(), a.getCreatedAt(), a.isAllowAuthenticated());
        }
    }
}
