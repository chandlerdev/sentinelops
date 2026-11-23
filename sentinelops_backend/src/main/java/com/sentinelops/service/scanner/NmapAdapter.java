package com.sentinelops.service.scanner;

import com.sentinelops.config.AppProperties;
import com.sentinelops.entity.ScanCategory;
import com.sentinelops.entity.ScanMode;
import com.sentinelops.entity.Severity;
import com.sentinelops.entity.TargetKind;
import org.springframework.stereotype.Component;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Nmap TCP connect scan of the top 100 ports. Connect scan only (no raw packets, no extra capabilities).
 * Version detection is added only in ACTIVE mode. Domains are scanned by their gate-verified addresses.
 */
@Component
public class NmapAdapter implements ScannerAdapter {

    /** Ports whose exposure to the internet is usually a mistake. */
    private static final Map<Integer, Severity> RISKY = Map.ofEntries(
            Map.entry(21, Severity.MEDIUM), Map.entry(23, Severity.HIGH), Map.entry(135, Severity.MEDIUM),
            Map.entry(139, Severity.MEDIUM), Map.entry(445, Severity.MEDIUM), Map.entry(1433, Severity.MEDIUM),
            Map.entry(2375, Severity.HIGH), Map.entry(3306, Severity.MEDIUM), Map.entry(3389, Severity.MEDIUM),
            Map.entry(5432, Severity.MEDIUM), Map.entry(5900, Severity.MEDIUM), Map.entry(6379, Severity.HIGH),
            Map.entry(9200, Severity.HIGH), Map.entry(11211, Severity.HIGH), Map.entry(27017, Severity.HIGH));

    @Override public String id() { return "nmap"; }

    @Override public boolean supports(ScanCategory c) { return c == ScanCategory.NETWORK; }

    @Override public String image(AppProperties.Engine e) { return e.getNmapImage(); }

    @Override public String outputFile() { return "nmap.xml"; }

    @Override
    public List<String> command(ScanContext ctx) {
        List<String> c = new ArrayList<>(List.of("-sT", "-Pn", "-n", "--top-ports", "100", "--open",
                "--max-retries", "2", "-T3", "-oX", containerOutDir() + "/" + outputFile()));
        if (ctx.mode() == ScanMode.ACTIVE) {
            c.add("-sV");
            c.add("--version-light");
        }
        if (ctx.kind() == TargetKind.DOMAIN) c.addAll(ctx.addresses());
        else c.add(ctx.host());
        return c;
    }

    @Override
    public List<NormalizedFinding> parse(Path outDir, ScanContext ctx) throws IOException {
        byte[] bytes = ScannerAdapter.readCapped(outDir.resolve(outputFile()));
        Document doc;
        try {
            DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
            f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            f.setXIncludeAware(false);
            f.setExpandEntityReferences(false);
            doc = f.newDocumentBuilder().parse(new ByteArrayInputStream(bytes));
        } catch (Exception ex) {
            throw new IOException("Unreadable nmap output", ex);
        }

        List<NormalizedFinding> out = new ArrayList<>();
        NodeList hosts = doc.getElementsByTagName("host");
        for (int i = 0; i < hosts.getLength(); i++) {
            Element host = (Element) hosts.item(i);
            String addr = "";
            NodeList addrs = host.getElementsByTagName("address");
            if (addrs.getLength() > 0) addr = ((Element) addrs.item(0)).getAttribute("addr");
            NodeList ports = host.getElementsByTagName("port");
            for (int p = 0; p < ports.getLength(); p++) {
                Element port = (Element) ports.item(p);
                NodeList st = port.getElementsByTagName("state");
                if (st.getLength() == 0 || !"open".equals(((Element) st.item(0)).getAttribute("state"))) continue;
                int number;
                try {
                    number = Integer.parseInt(port.getAttribute("portid"));
                } catch (NumberFormatException e) {
                    continue;
                }
                String proto = port.getAttribute("protocol");
                String service = "unknown";
                String detail = "";
                NodeList sv = port.getElementsByTagName("service");
                if (sv.getLength() > 0) {
                    Element s = (Element) sv.item(0);
                    if (!s.getAttribute("name").isBlank()) service = s.getAttribute("name");
                    detail = (s.getAttribute("product") + " " + s.getAttribute("version")).strip();
                }
                Severity sev = RISKY.getOrDefault(number, Severity.INFORMATIONAL);
                boolean risky = sev != Severity.INFORMATIONAL;
                out.add(new NormalizedFinding("open-port-" + proto + "-" + number,
                        "Open port " + number + "/" + proto + " (" + service + ")" + (risky ? " exposed" : ""),
                        sev, addr + ":" + number,
                        "Port " + number + "/" + proto + " accepts connections" + (detail.isEmpty() ? "." : " - " + detail + "."),
                        risky ? "Do not expose this service to the internet. Restrict it with a firewall to the networks that need it, "
                                + "and require authentication."
                              : "Confirm the service is intended to be public; close or firewall it otherwise.",
                        null));
            }
        }
        return out;
    }
}
