package com.example.authservice.service

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import org.springframework.stereotype.Service
import java.util.*
import javax.crypto.SecretKey

@Service
class JwtService {

    /**
     * In 2026, JJWT 0.13.x requires a SecretKey object.
     * Ensure this string is at least 32 characters long for HS256 compatibility.
     */
    private val secretKey: SecretKey = Keys.hmacShaKeyFor(
        "my-super-secret-key-for-jwt-2026-must-be-at-least-32-characters-long".toByteArray()
    )

    // Token Expiration Constants
    private val ACCESS_TOKEN_EXPIRATION = 15 * 60 * 1000 // 15 Minutes
    private val REFRESH_TOKEN_EXPIRATION = 7 * 24 * 60 * 60 * 1000 // 7 Days

    /**
     * Generates a short-lived Access Token for API authentication.
     */
    fun generateAccessToken(username: String): String {
        return createToken(username, ACCESS_TOKEN_EXPIRATION)
    }

    /**
     * Generates a long-lived Refresh Token to request new Access Tokens.
     */
    fun generateRefreshToken(username: String): String {
        return createToken(username, REFRESH_TOKEN_EXPIRATION)
    }

    /**
     * Generic builder for JWT tokens using modern JJWT 0.13.0 syntax.
     */
    private fun createToken(username: String, expirationMillis: Int): String {
        val now = Date()
        val expiry = Date(now.time + expirationMillis)

        return Jwts.builder()
            .subject(username)
            .issuedAt(now)
            .expiration(expiry)
            .signWith(secretKey)
            .compact()
    }

    /**
     * Modern Validation: Checks signature, expiration, and token integrity.
     * Replaces the deprecated 'parseClaimsJws' with 'parseSignedClaims'.
     */
    fun validateToken(token: String): Boolean {
        return try {
            getClaims(token)
            true
        } catch (e: Exception) {
            // Logs or specific exception handling (ExpiredJwtException, etc.) would go here
            false
        }
    }

    /**
     * Extracts the username (Subject) from the JWT payload.
     */
    fun extractUsername(token: String): String {
        return getClaims(token).subject
    }

    /**
     * Internal helper to parse the token using the modern parser builder.
     */
    private fun getClaims(token: String): Claims {
        return Jwts.parser()
            .verifyWith(secretKey) // Replaces setSigningKey()
            .build()
            .parseSignedClaims(token) // Replaces parseClaimsJws()
            .payload // Replaces .body
    }
}
