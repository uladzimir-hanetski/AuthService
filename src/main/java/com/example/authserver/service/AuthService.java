package com.example.authserver.service;

import com.example.authserver.dto.AuthRequest;
import com.example.authserver.dto.AuthResponse;
import com.example.authserver.entity.UserCredentials;
import com.example.authserver.exception.LoginAlreadyExistsException;
import com.example.authserver.exception.UserNotFoundException;
import com.example.authserver.mapper.AuthMapper;
import com.example.authserver.repository.AuthRepository;
import com.example.authserver.util.SecurityUtil;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final AuthRepository authRepository;
    private final AuthMapper authMapper;
    private final PasswordEncoder passwordEncoder;
    private final SecurityUtil securityUtil;

    public void register(AuthRequest authRequest) {
        if (authRepository.existsByLogin(authRequest.getLogin()))
            throw new LoginAlreadyExistsException("Login already exists");

        UserCredentials userCredentials = authMapper.toEntity(authRequest);
        userCredentials.setPassword(passwordEncoder.encode(authRequest.getPassword()));

        authRepository.save(userCredentials);
    }

    public AuthResponse login(AuthRequest authRequest) {
        UserCredentials user = authRepository.findByLogin(authRequest.getLogin())
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        if (!passwordEncoder.matches(authRequest.getPassword(), user.getPassword()))
            throw new BadCredentialsException("Wrong password");

        String accessToken = securityUtil.getAccessToken(user.getId());
        String refreshToken = securityUtil.getRefreshToken(user.getId());

        return new AuthResponse(accessToken, refreshToken);
    }

    public AuthResponse refresh(String tokenHeader) {
        String token = getTokenFromHeader(tokenHeader);
        if (!securityUtil.isRefreshToken(token)) throw new JwtException("Invalid token type");

        UUID userId = securityUtil.getUserIdFromToken(token);

        String accessToken = securityUtil.getAccessToken(userId);
        String refreshToken = securityUtil.getRefreshToken(userId);

        return new AuthResponse(accessToken, refreshToken);
    }

    public Boolean validate(String tokenHeader) {
        return securityUtil.validateToken(getTokenFromHeader(tokenHeader));
    }

    private String getTokenFromHeader(String header) {
        if (header != null && header.startsWith("Bearer ")) return header.substring(7);
        else throw new JwtException("Invalid <Authorization> header type");
    }
}
