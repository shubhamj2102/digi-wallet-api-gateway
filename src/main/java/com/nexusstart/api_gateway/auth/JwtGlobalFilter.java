package com.nexusstart.api_gateway.auth;

import com.nexusstart.api_gateway.service.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class JwtGlobalFilter implements GlobalFilter, Ordered {

    @Autowired
    private JwtService jwtService; // Your JWT logic

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        // 1. BYPASS LOGIN: Don't check tokens for Auth/Login paths
        if (isPublicUrl(request.getURI().getPath())) {
            return chain.filter(exchange);
        }

        // 2. INTERCEPT: Check for Authorization Header
        if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
            return onError(exchange, "Missing Authorization Header", HttpStatus.UNAUTHORIZED);
        }

        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        String token = authHeader.substring(7); // Remove "Bearer "

        // 3. VALIDATE: If token is invalid, stop the request here!
        if (!jwtService.isValid(token)) {
            return onError(exchange, "Invalid JWT Token", HttpStatus.UNAUTHORIZED);
        }

        // 4. ENRICH: Extract info from JWT and add to headers for Chat/Pulse services
        String userEmail = jwtService.extractEmail(token);
        String userRole = jwtService.extractRole(token);

        ServerHttpRequest mutatedRequest = request.mutate()
                .header("X-User-Email", userEmail)
                .header("X-User-Role", userRole)
                .build();

        // 5. PROCEED: Hand the "mutated" request to the next filter/microservice
        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }

    private boolean isPublicUrl(String path) {
        return path.contains("/api/v1/auth/login") ||
                path.contains("/api/v1/auth/register") ||
                path.contains("/api/v1/auth/forgot-password") ||
                path.contains("/api/v1/auth/existing-employee");

    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus status) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        return response.setComplete();
    }

    @Override
    public int getOrder() {
        return -1; // Run this before any other filter
    }
}