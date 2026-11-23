package com.sentinelops.dto;

public record LoginResponse(String token, String role, int expiresInMinutes) {}
