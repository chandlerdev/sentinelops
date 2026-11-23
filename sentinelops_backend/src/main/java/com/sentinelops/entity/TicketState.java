package com.sentinelops.entity;

public enum TicketState {
    NEW,
    DISCOVERY,
    PROPOSAL_SENT,
    PROPOSAL_APPROVED,
    AWAITING_AUTHORIZATION,
    AUTHORIZED,
    TESTING,
    REPORTED,
    REMEDIATION,
    RETESTING,
    VERIFYING,
    CLOSED,
    DECLINED
}
