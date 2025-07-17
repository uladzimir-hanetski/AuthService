package com.example.authserver.dto;

import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@RequiredArgsConstructor
public class AuthResponse {
    private final String accessToken;
    private final String refreshToken;
}
