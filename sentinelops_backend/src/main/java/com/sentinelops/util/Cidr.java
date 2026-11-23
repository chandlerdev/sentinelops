package com.sentinelops.util;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.regex.Pattern;

/** IPv4 / IPv6 CIDR block with containment and overlap checks. Parses literals only, never does DNS. */
public final class Cidr {

    private static final Pattern IPV4 = Pattern.compile(
            "^(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}$");
    private static final Pattern IPV6 = Pattern.compile("^[0-9a-fA-F:.]{2,45}$");

    private final BigInteger network;
    private final int prefix;
    private final int bits;

    private Cidr(BigInteger network, int prefix, int bits) {
        this.network = network;
        this.prefix = prefix;
        this.bits = bits;
    }

    /** Parses "a.b.c.d/len", "x::/len" or a bare IP literal (single host). */
    public static Cidr parse(String text) {
        if (text == null) throw new IllegalArgumentException("Empty address");
        String s = text.trim();
        String addr = s;
        Integer len = null;
        int slash = s.indexOf('/');
        if (slash >= 0) {
            addr = s.substring(0, slash);
            try {
                len = Integer.parseInt(s.substring(slash + 1));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid prefix length in '" + text + "'");
            }
        }
        InetAddress ip = parseLiteral(addr);
        int bits = ip.getAddress().length * 8;
        int prefix = len == null ? bits : len;
        if (prefix < 0 || prefix > bits) throw new IllegalArgumentException("Prefix length out of range in '" + text + "'");
        BigInteger raw = new BigInteger(1, ip.getAddress());
        return new Cidr(raw.and(mask(bits, prefix)), prefix, bits);
    }

    /** True if the text is an IPv4/IPv6 literal (no DNS lookup is performed). */
    public static boolean isIpLiteral(String s) {
        if (s == null) return false;
        String t = s.trim();
        if (IPV4.matcher(t).matches()) return true;
        return t.contains(":") && IPV6.matcher(t).matches() && tryLiteral(t) != null;
    }

    public static InetAddress parseLiteral(String s) {
        String t = s == null ? "" : s.trim();
        if (!isIpLiteral(t)) throw new IllegalArgumentException("'" + s + "' is not an IP address");
        InetAddress a = tryLiteral(t);
        if (a == null) throw new IllegalArgumentException("'" + s + "' is not an IP address");
        return a;
    }

    private static InetAddress tryLiteral(String t) {
        try {
            // Safe: literals never trigger a DNS lookup (guarded by the regexes above).
            return InetAddress.getByName(t);
        } catch (UnknownHostException e) {
            return null;
        }
    }

    private static BigInteger mask(int bits, int prefix) {
        BigInteger all = BigInteger.ONE.shiftLeft(bits).subtract(BigInteger.ONE);
        BigInteger host = BigInteger.ONE.shiftLeft(bits - prefix).subtract(BigInteger.ONE);
        return all.xor(host);
    }

    public boolean isIpv4() { return bits == 32; }
    public int prefix() { return prefix; }

    public boolean contains(InetAddress a) {
        byte[] raw = a.getAddress();
        if (raw.length * 8 != bits) return false;
        return new BigInteger(1, raw).and(mask(bits, prefix)).equals(network);
    }

    public boolean overlaps(Cidr o) {
        if (o.bits != bits) return false;
        BigInteger lowA = network, highA = network.or(hostMask());
        BigInteger lowB = o.network, highB = o.network.or(o.hostMask());
        return lowA.compareTo(highB) <= 0 && lowB.compareTo(highA) <= 0;
    }

    /** True if every address of this block lies inside {@code o}. */
    public boolean isInside(Cidr o) {
        if (o.bits != bits || prefix < o.prefix) return false;
        return network.and(mask(bits, o.prefix)).equals(o.network);
    }

    private BigInteger hostMask() {
        return BigInteger.ONE.shiftLeft(bits - prefix).subtract(BigInteger.ONE);
    }

    @Override
    public String toString() {
        return network.toString(16) + "/" + prefix;
    }
}
