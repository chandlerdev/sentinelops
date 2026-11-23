package com.sentinelops.service;

import com.sentinelops.entity.TicketState;
import java.util.List;
import java.util.Map;

import static com.sentinelops.entity.TicketState.*;

/** Ticket lifecycle state machine. Transitions not listed are rejected. */
public final class StateMachine {

    private static final Map<TicketState, List<TicketState>> TRANSITIONS = Map.ofEntries(
            Map.entry(NEW, List.of(DISCOVERY, DECLINED)),
            Map.entry(DISCOVERY, List.of(PROPOSAL_SENT, DECLINED)),
            Map.entry(PROPOSAL_SENT, List.of(PROPOSAL_APPROVED, DECLINED)),
            Map.entry(PROPOSAL_APPROVED, List.of(AWAITING_AUTHORIZATION)),
            Map.entry(AWAITING_AUTHORIZATION, List.of(AUTHORIZED, DECLINED)),
            Map.entry(AUTHORIZED, List.of(TESTING, AWAITING_AUTHORIZATION)),
            Map.entry(TESTING, List.of(REPORTED, AUTHORIZED)),
            Map.entry(REPORTED, List.of(REMEDIATION)),
            Map.entry(REMEDIATION, List.of(RETESTING)),
            Map.entry(RETESTING, List.of(VERIFYING)),
            Map.entry(VERIFYING, List.of(CLOSED, REMEDIATION)),
            Map.entry(CLOSED, List.of()),
            Map.entry(DECLINED, List.of())
    );

    private StateMachine() {}

    public static boolean canTransition(TicketState from, TicketState to) {
        return TRANSITIONS.getOrDefault(from, List.of()).contains(to);
    }

    public static void assertTransition(TicketState from, TicketState to) {
        if (!canTransition(from, to)) {
            throw new IllegalStateException("Illegal ticket transition: " + from + " -> " + to);
        }
    }
}
