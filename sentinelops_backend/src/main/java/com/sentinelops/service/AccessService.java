package com.sentinelops.service;

import com.sentinelops.entity.Engagement;
import com.sentinelops.entity.Role;
import com.sentinelops.entity.Target;
import com.sentinelops.entity.User;
import com.sentinelops.exception.NotFoundException;
import com.sentinelops.repository.EngagementRepository;
import com.sentinelops.repository.TargetRepository;
import com.sentinelops.repository.UserRepository;
import com.sentinelops.util.CurrentUser;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;

/** Object-level access rules: a CLIENT user may only see their own client's engagements. */
@Service
public class AccessService {

    private final UserRepository users;
    private final EngagementRepository engagements;
    private final TargetRepository targets;

    public AccessService(UserRepository users, EngagementRepository engagements, TargetRepository targets) {
        this.users = users;
        this.engagements = engagements;
        this.targets = targets;
    }

    public User currentUser() {
        return users.findByEmail(CurrentUser.email())
                .filter(User::isActive)
                .orElseThrow(() -> new AccessDeniedException("Access denied"));
    }

    /** Loads an engagement and enforces that the current user may see it. */
    public Engagement requireEngagement(String id) {
        Engagement e = engagements.findById(id).orElseThrow(() -> new NotFoundException("Engagement not found"));
        User u = currentUser();
        if (u.getRole() == Role.CLIENT && (u.getClientId() == null || !u.getClientId().equals(e.getClientId()))) {
            throw new AccessDeniedException("Access denied");
        }
        return e;
    }

    /** Loads a target and enforces access to its engagement. */
    public Target requireTarget(String targetId) {
        Target t = targets.findById(targetId).orElseThrow(() -> new NotFoundException("Target not found"));
        requireEngagement(t.getEngagementId());
        return t;
    }
}
