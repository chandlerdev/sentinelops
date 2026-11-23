package com.sentinelops.service;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;

/** DNS resolution seam so scope checks can be tested with fake DNS (rebinding, changes between checks). */
public interface HostResolver {
    List<InetAddress> resolve(String host) throws UnknownHostException;
}
