package com.sentinelops.service;

import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;

/** Resolves through the operating system resolver, every time (no caching of our own). */
@Component
public class SystemHostResolver implements HostResolver {
    @Override
    public List<InetAddress> resolve(String host) throws UnknownHostException {
        return Arrays.asList(InetAddress.getAllByName(host));
    }
}
