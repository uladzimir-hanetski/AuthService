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
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<Void> register(@Valid @RequestBody AuthRequest authRequest) {
        authService.register(authRequest);
        return ResponseEntity.status(HttpStatus.CREATED).build();
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
