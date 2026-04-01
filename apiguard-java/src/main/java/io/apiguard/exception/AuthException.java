package io.apiguard.exception;

/**
 * Thrown by {@link io.apiguard.jwt.JwtValidator} when a token
 * is missing, expired, malformed, or has an invalid signature.
 * Maps to HTTP 401 Unauthorized.
 */
public class AuthException extends RuntimeException {

    public AuthException(String message) {
        super(message);
    }

    public AuthException(String message, Throwable cause) {
        super(message, cause);
    }
}
