package com.sentinelops.service;

import java.util.List;

/** Looks up TXT records for a DNS name (independent resolver; faked in tests). */
public interface TxtLookup {
    List<String> lookup(String name) throws Exception;
}
