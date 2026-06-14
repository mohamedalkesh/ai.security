package com.aisec.backend.websocket;

import com.aisec.backend.dto.alert.AlertDto;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;

import java.io.IOException;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Per-tenant WebSocket broadcaster.
 *
 * Every WS session carries an "orgId" attribute (populated by JwtHandshakeInterceptor
 * from the JWT claim). Messages are only delivered to sessions whose orgId matches the
 * orgId of the originating data. The system tenant (orgId == null) is just another
 * isolated namespace — no cross-tenant leakage in either direction.
 */
@Component
public class AlertBroadcaster {

    private static final Logger log = LoggerFactory.getLogger(AlertBroadcaster.class);
    private static final String ORG_ATTR = "orgId";

    private final Set<WebSocketSession> sessions = ConcurrentHashMap.newKeySet();
    private final ObjectMapper mapper;

    public AlertBroadcaster(ObjectMapper mapper) { this.mapper = mapper; }

    public void register(WebSocketSession s)   { sessions.add(s); }
    public void unregister(WebSocketSession s) { sessions.remove(s); }
    public int connectedCount() { return sessions.size(); }

    /** Broadcast an alert to sessions of the alert's owning tenant only. */
    public void broadcast(AlertDto alert, Long ownerOrgId) {
        sendToTenant(Map.of("type", "alert", "data", alert), ownerOrgId);
    }

    /** Broadcast a scan-complete event to sessions of the scan's owning tenant only. */
    public void broadcastScanComplete(Object summary, Long ownerOrgId) {
        sendToTenant(Map.of("type", "scan_complete", "data", summary), ownerOrgId);
    }

    private void sendToTenant(Map<String, Object> envelope, Long ownerOrgId) {
        if (sessions.isEmpty()) return;
        try {
            String payload = mapper.writeValueAsString(envelope);
            TextMessage msg = new TextMessage(payload);
            for (WebSocketSession s : sessions) {
                if (!s.isOpen()) continue;
                Long sessOrgId = (Long) s.getAttributes().get(ORG_ATTR);
                // Strict equality — null only equals null, no wildcards.
                if (!Objects.equals(sessOrgId, ownerOrgId)) continue;
                try { s.sendMessage(msg); }
                catch (IOException ex) { log.warn("WS send failed: {}", ex.getMessage()); }
            }
        } catch (JsonProcessingException e) {
            log.error("Failed to serialise WS payload: {}", e.getMessage());
        }
    }
}
