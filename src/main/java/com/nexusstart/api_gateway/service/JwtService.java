package com.nexusstart.api_gateway.service;

import io.jsonwebtoken.Claims;

import java.util.function.Function;

public interface JwtService {
    // Extract the username (email) from the token
    String extractEmail(String token);

    // Generic method to extract any claim (like role or userId)
    <T> T extractClaim(String token, Function<Claims, T> claimsResolver);

    //  Specific method for Roles
    String extractRole(String token);

    // Main validation method
    boolean isValid(String token);
}
