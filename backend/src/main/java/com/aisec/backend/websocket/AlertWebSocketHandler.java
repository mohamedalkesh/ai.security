package com.aisec.backend.websocket;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;

@Component
public class AlertWebSocketHandler extends TextWebSocketHandler {

    private static final Logger log = LoggerFactory.getLogger(AlertWebSocketHandler.class);
    private final AlertBroadcaster broadcaster;

    public AlertWebSocketHandler(AlertBroadcaster broadcaster) { this.broadcaster = broadcaster; }

    @Override
    public void afterConnectionEstablished(@NonNull WebSocketSession session) throws Exception {
        broadcaster.register(session);
        session.sendMessage(new TextMessage("{\"type\":\"hello\",\"connected\":" + broadcaster.connectedCount() + "}"));
        log.info("WS client connected ({} total)", broadcaster.connectedCount());
    }

    @Override
    public void afterConnectionClosed(@NonNull WebSocketSession session, @NonNull CloseStatus status) {
        broadcaster.unregister(session);
        log.info("WS client disconnected ({} total)", broadcaster.connectedCount());
    }
}
