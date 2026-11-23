package com.sentinelops.service;

import com.sentinelops.entity.Engagement;
import com.sentinelops.entity.Role;
import com.sentinelops.entity.TicketState;
import com.sentinelops.entity.User;
import com.sentinelops.exception.NotFoundException;
import com.sentinelops.repository.ClientRepository;
import com.sentinelops.repository.EngagementRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
public class EngagementService {

    private final EngagementRepository engagements;
    private final ClientRepository clients;
    private final AccessService access;
    private final AuditService audit;

    public EngagementService(EngagementRepository engagements, ClientRepository clients,
                             AccessService access, AuditService audit) {
        this.engagements = engagements;
        this.clients = clients;
        this.access = access;
        this.audit = audit;
    }

    @Transactional(readOnly = true)
    public List<Engagement> list() {
        User u = access.currentUser();
        if (u.getRole() == Role.CLIENT) {
            return u.getClientId() == null ? List.of() : engagements.findByClientId(u.getClientId());
        }
        return engagements.findAll();
    }

    @Transactional(readOnly = true)
    public Engagement get(String id) {
        return access.requireEngagement(id);
    }

    /**
     * New engagements start at AWAITING_AUTHORIZATION: the sales steps (discovery, proposal) are outside
     * this platform's current scope, so work begins with targets and the written authorization.
     */
    @PreAuthorize("hasAnyRole('MANAGER','ADMIN')")
    @Transactional
    public Engagement create(String name, String clientId, String environment,
                             Instant windowStart, Instant windowEnd, String actor) {
        clients.findById(clientId).orElseThrow(() -> new NotFoundException("Client not found"));
        if (windowStart != null && windowEnd != null && !windowEnd.isAfter(windowStart)) {
            throw new IllegalArgumentException("The engagement window end must be after its start.");
        }
        Engagement e = new Engagement(UUID.randomUUID().toString(), name.trim(), clientId, environment);
        e.setState(TicketState.AWAITING_AUTHORIZATION);
        e.setWindowStart(windowStart);
        e.setWindowEnd(windowEnd);
        engagements.save(e);
        audit.record(actor, "engagement.created", "Engagement", e.getId(), "client=" + clientId + " name=" + e.getName());
        return e;
    }
}
