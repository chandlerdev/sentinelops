package com.sentinelops.service;

import com.sentinelops.config.AppProperties;
import org.springframework.stereotype.Component;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

/**
 * TXT lookup through the JDK's built-in DNS client, pointed at independent public resolvers
 * (configurable) so the check does not depend on the server's own resolver cache or split DNS.
 */
@Component
public class JndiTxtLookup implements TxtLookup {

    private final AppProperties props;

    public JndiTxtLookup(AppProperties props) {
        this.props = props;
    }

    @Override
    public List<String> lookup(String name) throws Exception {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
        List<String> servers = props.getVerification().getDnsServers();
        if (!servers.isEmpty()) {
            StringBuilder url = new StringBuilder();
            for (String s : servers) {
                if (s != null && !s.isBlank()) url.append("dns://").append(s.trim()).append(' ');
            }
            env.put(Context.PROVIDER_URL, url.toString().trim());
        }
        env.put("com.sun.jndi.dns.timeout.initial", "3000");
        env.put("com.sun.jndi.dns.timeout.retries", "1");

        DirContext ctx = new InitialDirContext(env);
        try {
            Attributes attrs = ctx.getAttributes(name, new String[]{"TXT"});
            Attribute txt = attrs.get("TXT");
            List<String> out = new ArrayList<>();
            if (txt != null) {
                NamingEnumeration<?> e = txt.getAll();
                while (e.hasMore()) {
                    // Values may arrive quoted and split in several quoted chunks: join and strip quotes.
                    out.add(String.valueOf(e.next()).replace("\"", "").trim());
                }
            }
            return out;
        } finally {
            ctx.close();
        }
    }
}
