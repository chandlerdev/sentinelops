package com.sentinelops.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * Strongly-typed app config, read from application.properties (prefix "sentinelops").
 * No secret has a usable default; see validation in JwtService.
 */
@ConfigurationProperties(prefix = "sentinelops")
public class AppProperties {

    private final Security security = new Security();
    private final Scan scan = new Scan();
    private final Verification verification = new Verification();

    public Security getSecurity() { return security; }
    public Scan getScan() { return scan; }
    public Verification getVerification() { return verification; }

    public static class Security {
        private String jwtSecret = "";
        /** Base64 of 32 random bytes. Encrypts stored scan credentials. Empty = credential storage is refused. */
        private String secretKey = "";
        private int jwtTtlMinutes = 30;
        private String corsAllowedOrigins = "http://localhost:3200";
        private int rateLimitPerMinute = 100;
        /** The person who approves an authorization must differ from the person who requested it. */
        private boolean fourEyes = true;
        /** Longest testing window an authorization may grant. */
        private int maxWindowDays = 90;

        public String getSecretKey() { return secretKey; }
        public void setSecretKey(String v) { this.secretKey = v == null ? "" : v; }
        public String getJwtSecret() { return jwtSecret; }
        public void setJwtSecret(String v) { this.jwtSecret = v; }
        public int getJwtTtlMinutes() { return jwtTtlMinutes; }
        public void setJwtTtlMinutes(int v) { this.jwtTtlMinutes = v; }
        public String getCorsAllowedOrigins() { return corsAllowedOrigins; }
        public void setCorsAllowedOrigins(String v) { this.corsAllowedOrigins = v; }
        public int getRateLimitPerMinute() { return rateLimitPerMinute; }
        public void setRateLimitPerMinute(int v) { this.rateLimitPerMinute = v; }
        public boolean isFourEyes() { return fourEyes; }
        public void setFourEyes(boolean v) { this.fourEyes = v; }
        public int getMaxWindowDays() { return maxWindowDays; }
        public void setMaxWindowDays(int v) { this.maxWindowDays = v; }
    }

    public static class Scan {
        private String identifierHeader = "X-Pentest";
        /** Extra addresses that must never be scanned (e.g. this server's public IP). */
        private List<String> blockedAddresses = new ArrayList<>();
        private int minIpv4Prefix = 24;
        private int minIpv6Prefix = 120;
        private final Lab lab = new Lab();
        private final Engine engine = new Engine();

        public String getIdentifierHeader() { return identifierHeader; }
        public void setIdentifierHeader(String v) { this.identifierHeader = v; }
        public List<String> getBlockedAddresses() { return blockedAddresses; }
        public void setBlockedAddresses(List<String> v) { this.blockedAddresses = v == null ? new ArrayList<>() : v; }
        public int getMinIpv4Prefix() { return minIpv4Prefix; }
        public void setMinIpv4Prefix(int v) { this.minIpv4Prefix = v; }
        public int getMinIpv6Prefix() { return minIpv6Prefix; }
        public void setMinIpv6Prefix(int v) { this.minIpv6Prefix = v; }
        public Lab getLab() { return lab; }
        public Engine getEngine() { return engine; }
    }

    /**
     * Controlled-laboratory exception (our own Juice Shop on a dedicated Docker network).
     * Private addresses are reachable ONLY for lab targets, ONLY inside these CIDRs, ONLY for these hosts.
     */
    public static class Lab {
        private boolean enabled = false;
        private List<String> cidrs = new ArrayList<>();
        private List<String> hosts = new ArrayList<>();

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean v) { this.enabled = v; }
        public List<String> getCidrs() { return cidrs; }
        public void setCidrs(List<String> v) { this.cidrs = v == null ? new ArrayList<>() : v; }
        public List<String> getHosts() { return hosts; }
        public void setHosts(List<String> v) { this.hosts = v == null ? new ArrayList<>() : v; }
    }

    /**
     * The scan engine runs each tool in a short-lived Docker container built from a FIXED command template.
     * Disabled by default: nothing is queued or executed until an operator turns it on.
     */
    public static class Engine {
        private boolean enabled = false;
        private String dockerBinary = "docker";
        /** Where raw tool output is kept (one folder per scan run). */
        private String workDir = "./scan-work";
        /** Docker network for scans of external targets. Empty = Docker's default bridge. */
        private String scanNetwork = "";
        /** Docker network of the lab (our own Juice Shop). Lab targets are scanned ONLY on this network. */
        private String labNetwork = "sentinelops-lab";
        private int maxConcurrent = 1;
        private int pollMs = 5000;
        private int timeoutMinutes = 30;
        private String cpus = "1";
        private String memory = "1g";
        private String nucleiImage = "projectdiscovery/nuclei:latest";
        private String zapImage = "ghcr.io/zaproxy/zaproxy:stable";
        private String testsslImage = "drwetter/testssl.sh:3.2";
        private String nmapImage = "instrumentisto/nmap:latest";
        /** "npm" binary on the SERVER (not Docker): runs "npm audit" against an uploaded package-lock.json. */
        private String npmBinary = "npm";
        private int npmAuditTimeoutSeconds = 60;
        /**
         * Host folder with pre-downloaded nuclei templates (run "nuclei -update-templates" into it once, with
         * normal internet access). Mounted read-only into every nuclei container. Required for LAB targets,
         * since the lab network has no internet access and nuclei cannot download templates there itself.
         * Empty = not configured; nuclei falls back to its own default behaviour (fine for non-lab targets
         * on a network with internet access, but lab scans will fail with "no templates provided for scan").
         */
        private String nucleiTemplatesDir = "";

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean v) { this.enabled = v; }
        public String getDockerBinary() { return dockerBinary; }
        public void setDockerBinary(String v) { this.dockerBinary = v; }
        public String getWorkDir() { return workDir; }
        public void setWorkDir(String v) { this.workDir = v; }
        public String getScanNetwork() { return scanNetwork; }
        public void setScanNetwork(String v) { this.scanNetwork = v == null ? "" : v; }
        public String getLabNetwork() { return labNetwork; }
        public void setLabNetwork(String v) { this.labNetwork = v; }
        public int getMaxConcurrent() { return maxConcurrent; }
        public void setMaxConcurrent(int v) { this.maxConcurrent = Math.max(1, v); }
        public int getPollMs() { return pollMs; }
        public void setPollMs(int v) { this.pollMs = Math.max(500, v); }
        public int getTimeoutMinutes() { return timeoutMinutes; }
        public void setTimeoutMinutes(int v) { this.timeoutMinutes = Math.max(1, v); }
        public String getCpus() { return cpus; }
        public void setCpus(String v) { this.cpus = v; }
        public String getMemory() { return memory; }
        public void setMemory(String v) { this.memory = v; }
        public String getNucleiImage() { return nucleiImage; }
        public void setNucleiImage(String v) { this.nucleiImage = v; }
        public String getZapImage() { return zapImage; }
        public void setZapImage(String v) { this.zapImage = v; }
        public String getTestsslImage() { return testsslImage; }
        public void setTestsslImage(String v) { this.testsslImage = v; }
        public String getNmapImage() { return nmapImage; }
        public void setNmapImage(String v) { this.nmapImage = v; }
        public String getNpmBinary() { return npmBinary; }
        public void setNpmBinary(String v) { this.npmBinary = v; }
        public int getNpmAuditTimeoutSeconds() { return npmAuditTimeoutSeconds; }
        public void setNpmAuditTimeoutSeconds(int v) { this.npmAuditTimeoutSeconds = Math.max(5, v); }
        public String getNucleiTemplatesDir() { return nucleiTemplatesDir; }
        public void setNucleiTemplatesDir(String v) { this.nucleiTemplatesDir = v == null ? "" : v; }
    }

    public static class Verification {
        /** Independent DNS servers used for TXT checks (empty = system resolver). */
        private List<String> dnsServers = new ArrayList<>(List.of("1.1.1.1", "8.8.8.8"));
        /** How long a verification challenge token stays valid. */
        private int challengeHours = 72;
        /** How long a successful verification stays valid before it must be repeated. */
        private int validDays = 30;
        private int httpTimeoutSeconds = 8;

        public List<String> getDnsServers() { return dnsServers; }
        public void setDnsServers(List<String> v) { this.dnsServers = v == null ? new ArrayList<>() : v; }
        public int getChallengeHours() { return challengeHours; }
        public void setChallengeHours(int v) { this.challengeHours = v; }
        public int getValidDays() { return validDays; }
        public void setValidDays(int v) { this.validDays = v; }
        public int getHttpTimeoutSeconds() { return httpTimeoutSeconds; }
        public void setHttpTimeoutSeconds(int v) { this.httpTimeoutSeconds = v; }
    }
}
