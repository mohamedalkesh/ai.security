package com.aisec.backend.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app")
public class AppProperties {

    private final Cors cors = new Cors();
    private final Ml ml = new Ml();
    private final Firewall firewall = new Firewall();
    private final ThreatIntel threatIntel = new ThreatIntel();
    private final Security security = new Security();
    private String supportEmail = "MADRS.support@gmail.com";
    private String frontendUrl = "http://127.0.0.1:5500";

    public Cors getCors() { return cors; }
    public Ml getMl() { return ml; }
    public Firewall getFirewall() { return firewall; }
    public ThreatIntel getThreatIntel() { return threatIntel; }
    public Security getSecurity() { return security; }
    public String getSupportEmail() { return supportEmail; }
    public void setSupportEmail(String supportEmail) { this.supportEmail = supportEmail; }
    public String getFrontendUrl() { return frontendUrl; }
    public void setFrontendUrl(String frontendUrl) { this.frontendUrl = frontendUrl; }

    public static class Cors {
        private String allowedOrigins = "";
        public String getAllowedOrigins() { return allowedOrigins; }
        public void setAllowedOrigins(String allowedOrigins) { this.allowedOrigins = allowedOrigins; }
        public String[] originsArray() {
            if (allowedOrigins == null || allowedOrigins.isBlank()) return new String[0];
            return allowedOrigins.split("\\s*,\\s*");
        }
    }

    public static class Ml {
        private String baseUrl = "http://127.0.0.1:8001";
        private int connectTimeoutMs = 5000;
        private int readTimeoutMs = 120000;

        public String getBaseUrl() { return baseUrl; }
        public void setBaseUrl(String baseUrl) { this.baseUrl = baseUrl; }
        public int getConnectTimeoutMs() { return connectTimeoutMs; }
        public void setConnectTimeoutMs(int connectTimeoutMs) { this.connectTimeoutMs = connectTimeoutMs; }
        public int getReadTimeoutMs() { return readTimeoutMs; }
        public void setReadTimeoutMs(int readTimeoutMs) { this.readTimeoutMs = readTimeoutMs; }
    }

    /** Host-level packet-filter integration. See FirewallEnforcerFactory. */
    public static class Firewall {
        /** {@code auto} (default), {@code nftables}, or {@code noop}. */
        private String enforcer = "auto";
        /** Override binary path; empty = auto-probe usual locations. */
        private String nftPath = "";
        /** Wrap nft invocations with {@code sudo -n}. */
        private boolean useSudo = true;

        public String getEnforcer() { return enforcer; }
        public void setEnforcer(String enforcer) { this.enforcer = enforcer; }
        public String getNftPath() { return nftPath; }
        public void setNftPath(String nftPath) { this.nftPath = nftPath; }
        public boolean isUseSudo() { return useSudo; }
        public void setUseSudo(boolean useSudo) { this.useSudo = useSudo; }
    }

    /** External threat-intel providers (AbuseIPDB today; pluggable later). */
    public static class ThreatIntel {
        /** {@code auto} (use real if key present), {@code abuseipdb}, {@code mock}, {@code off}. */
        private String provider = "auto";
        private String abuseipdbKey = "";
        private String abuseipdbBaseUrl = "https://api.abuseipdb.com/api/v2";
        private int cacheTtlHours = 24;
        private int requestTimeoutMs = 5000;

        public String getProvider() { return provider; }
        public void setProvider(String provider) { this.provider = provider; }
        public String getAbuseipdbKey() { return abuseipdbKey; }
        public void setAbuseipdbKey(String abuseipdbKey) { this.abuseipdbKey = abuseipdbKey; }
        public String getAbuseipdbBaseUrl() { return abuseipdbBaseUrl; }
        public void setAbuseipdbBaseUrl(String abuseipdbBaseUrl) { this.abuseipdbBaseUrl = abuseipdbBaseUrl; }
        public int getCacheTtlHours() { return cacheTtlHours; }
        public void setCacheTtlHours(int cacheTtlHours) { this.cacheTtlHours = cacheTtlHours; }
        public int getRequestTimeoutMs() { return requestTimeoutMs; }
        public void setRequestTimeoutMs(int requestTimeoutMs) { this.requestTimeoutMs = requestTimeoutMs; }
    }

    public static class Security {
        /** Allow unauthenticated self-registration via /api/auth/register. */
        private boolean allowSelfRegister = false;

        public boolean isAllowSelfRegister() { return allowSelfRegister; }
        public void setAllowSelfRegister(boolean allowSelfRegister) {
            this.allowSelfRegister = allowSelfRegister;
        }
    }
}
