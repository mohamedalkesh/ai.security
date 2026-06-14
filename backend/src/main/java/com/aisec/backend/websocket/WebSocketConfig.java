package com.aisec.backend.websocket;

import org.springframework.context.annotation.Configuration;
import org.springframework.lang.NonNull;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;

@Configuration
@EnableWebSocket
public class WebSocketConfig implements WebSocketConfigurer {

    private final AlertWebSocketHandler handler;
    private final JwtHandshakeInterceptor jwtInterceptor;

    public WebSocketConfig(AlertWebSocketHandler handler, JwtHandshakeInterceptor jwtInterceptor) {
        this.handler = handler;
        this.jwtInterceptor = jwtInterceptor;
    }

    @Override
    public void registerWebSocketHandlers(@NonNull WebSocketHandlerRegistry registry) {
        registry.addHandler(handler, "/ws/alerts")
                .addInterceptors(jwtInterceptor)
                .setAllowedOriginPatterns("*");
    }
}
