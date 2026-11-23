package com.sentinelops.entity;

/** DRAFT -> PENDING_APPROVAL -> SIGNED (in force) | REJECTED; SIGNED -> REVOKED. */
public enum AuthStatus { DRAFT, PENDING_APPROVAL, SIGNED, REJECTED, REVOKED }
