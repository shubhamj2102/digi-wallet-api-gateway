
package com.nexusstart.api_gateway.auth;

import com.nexusstart.api_gateway.service.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
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

        // 0) Allow CORS preflight so browser can proceed
        if (HttpMethod.OPTIONS.equals(request.getMethod())) {
            return chain.filter(exchange);
        }

        // 1) Public URLs (ONLY your auth endpoints)
        String path = request.getURI().getPath();
        if (isPublicUrl(path)) {
            return chain.filter(exchange);
        }

        // 2) Require Authorization header with Bearer
        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return onError(exchange, "Missing or invalid Authorization header", HttpStatus.UNAUTHORIZED);
        }
        String token = authHeader.substring("Bearer ".length()).trim();
        if (token.isEmpty()) {
            return onError(exchange, "Empty bearer token", HttpStatus.UNAUTHORIZED);
        }

        // 3) Validate the token
        if (!jwtService.isValid(token)) {
            return onError(exchange, "Invalid JWT Token", HttpStatus.UNAUTHORIZED);
        }

        // 4) Extract trusted claims
        String userId = safe(jwtService.extractClaim(token, claims -> claims.get("userId", String.class)));
        String userEmail  = safe(jwtService.extractEmail(token));
        String userRole   = safe(jwtService.extractRole(token));
        String userStatus = safe(jwtService.extractClaim(token, claims -> claims.get("status", String.class))); // e.g., AwaitingOffer, Joined

        // 5) (Optional but recommended) Remove any spoofed incoming X-User-* headers
        ServerHttpRequest.Builder builder = request.mutate()
                // 6) Add trusted identity headers for downstream services
                .header("X-User-Id", userId)
                .header("X-User-Email", userEmail)
                .header("X-User-Role", userRole)
                .header("X-User-Status", userStatus);

        return chain.filter(exchange.mutate().request(builder.build()).build());
    }

    private boolean isPublicUrl(String path) {
        // Keep ONLY your public auth endpoints here
        if (path == null) return false;
        return path.startsWith("/api/v1/auth/login")
                || path.startsWith("/api/v1/auth/register")
                || path.startsWith("/api/v1/auth/forgot-password")
                || path.startsWith("/api/v1/auth/existing-employee");
    }

    private String safe(String v) {
        return v == null ? "" : v;
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus status) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        return response.setComplete();
    }

    @Override
    public int getOrder() {
        return -1; // Run early
    }
}
