package com.example.authserver.util;

import com.example.authserver.exception.ErrorResponse;
import com.example.authserver.exception.LoginAlreadyExistsException;
import com.example.authserver.exception.UserNotFoundException;
import io.jsonwebtoken.JwtException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler({UserNotFoundException.class, BadCredentialsException.class})
    public ResponseEntity<ErrorResponse> handleAuthException(RuntimeException ex) {
        ErrorResponse errorResponse = new ErrorResponse(HttpStatus.UNAUTHORIZED, "Authentication failed",
                ex.getMessage());

        return new ResponseEntity<>(errorResponse, errorResponse.getStatus());
    }

    @ExceptionHandler(JwtException.class)
    public ResponseEntity<ErrorResponse> handleJwtException(JwtException ex) {
        ErrorResponse errorResponse = new ErrorResponse(HttpStatus.UNAUTHORIZED, "Header's conflict",
                ex.getMessage());

        return new ResponseEntity<>(errorResponse, errorResponse.getStatus());
    }

    @ExceptionHandler(LoginAlreadyExistsException.class)
    public ResponseEntity<ErrorResponse> handleLoginAlreadyExistsException(RuntimeException ex) {
        ErrorResponse errorResponse = new ErrorResponse(HttpStatus.CONFLICT, "Invalid value",
                ex.getMessage());

        return new ResponseEntity<>(errorResponse, errorResponse.getStatus());
    }

    @ExceptionHandler(MissingRequestHeaderException.class)
    public ResponseEntity<ErrorResponse> handleMissingHeader() {
        ErrorResponse errorResponse = new ErrorResponse(HttpStatus.BAD_REQUEST, "Header's conflict",
                "Missing Authorization header");

        return new ResponseEntity<>(errorResponse, errorResponse.getStatus());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationException(
            MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(error ->
                errors.put(error.getField(), error.getDefaultMessage()));

        String error = errors.entrySet().stream().map(e ->
                e.getKey() + ": " + e.getValue()).collect(Collectors.joining("; "));
        ErrorResponse errorResponse = new ErrorResponse(HttpStatus.BAD_REQUEST, "Validation failed",
                error);

        return new ResponseEntity<>(errorResponse, errorResponse.getStatus());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleException(Exception ex) {
        ErrorResponse error = new ErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error",
                ex.getMessage());

        return new ResponseEntity<>(error, error.getStatus());
    }
}
