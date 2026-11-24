package com.sentinelops.entity;

/** How a logged-in session is carried on later requests, once the logic-testing modules replay them. */
public enum SessionType { HEADER_BEARER, COOKIE }
