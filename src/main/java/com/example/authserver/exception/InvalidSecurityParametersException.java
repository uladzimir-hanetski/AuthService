package com.example.authserver.exception;

public class InvalidSecurityParametersException extends RuntimeException {
    public InvalidSecurityParametersException(String message) {
        super(message);
    }
}
