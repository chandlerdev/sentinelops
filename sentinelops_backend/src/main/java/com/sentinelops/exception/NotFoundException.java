package com.sentinelops.exception;

/** Requested record does not exist (mapped to HTTP 404). */
public class NotFoundException extends RuntimeException {
    public NotFoundException(String message) { super(message); }
}
