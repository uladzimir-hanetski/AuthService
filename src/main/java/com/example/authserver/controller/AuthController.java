package com.example.authserver.controller;

import com.example.authserver.dto.AuthRequest;
import com.example.authserver.dto.AuthResponse;
import com.example.authserver.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.UUID;

@RestController
@RequestMapping("/v1/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/register/{id}")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody AuthRequest authRequest,
                                         @PathVariable("id") UUID id) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.register(authRequest, id));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody AuthRequest authRequest) {
        return ResponseEntity.ok(authService.login(authRequest));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String tokenHeader) {
        return ResponseEntity.ok(authService.refresh(tokenHeader));
    }

    @GetMapping("/validate")
    public ResponseEntity<Boolean> validate(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String tokenHeader) {
        return ResponseEntity.ok(authService.validate(tokenHeader));
    }
}
