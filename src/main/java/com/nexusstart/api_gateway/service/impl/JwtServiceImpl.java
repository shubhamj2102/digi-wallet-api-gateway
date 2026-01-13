package com.nexusstart.api_gateway.service.impl;

import com.nexusstart.api_gateway.service.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.function.Function;

@Service
public class JwtServiceImpl implements JwtService {

    @Value("${jwt.secret}")
    private String secretKey;

    // Helper to generate the signing key from your secret string
    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // Extract the username (email) from the token
    @Override
    public String extractEmail(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // Generic method to extract any claim (like role or userId)
    @Override
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    //  Specific method for Roles
    @Override
    public String extractRole(String token) {
        // This assumes your user-service put the role under the key "role" or "roles"
        return extractClaim(token, claims -> claims.get("role", String.class));
    }

    // Main validation method
    @Override
    public boolean isValid(String token) {
        try {
            // This will throw an exception if the token is expired or tampered with
            extractAllClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey()) // New 0.12.x way
                .build()
                .parseSignedClaims(token)
                .getPayload(); // New 0.12.x way (replaces getBody())
    }
}