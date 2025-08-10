package com.example.authserver.service;

import at.favre.lib.crypto.bcrypt.BCrypt;
import com.example.authserver.dto.AuthRequest;
import com.example.authserver.dto.AuthResponse;
import com.example.authserver.entity.UserCredentials;
import com.example.authserver.exception.BadCredentialsException;
import com.example.authserver.exception.LoginAlreadyExistsException;
import com.example.authserver.exception.UserNotFoundException;
import com.example.authserver.mapper.AuthMapper;
import com.example.authserver.repository.AuthRepository;
import com.example.authserver.util.SecurityUtil;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final AuthRepository authRepository;
    private final AuthMapper authMapper;
    private final SecurityUtil securityUtil;

    public AuthResponse register(AuthRequest authRequest, UUID id) {
        if (authRepository.existsByLogin(authRequest.getLogin()))
            throw new LoginAlreadyExistsException("Login already exists");

        UserCredentials userCredentials = authMapper.toEntity(authRequest);
        userCredentials.setPassword(BCrypt.withDefaults().hashToString(10, authRequest.getPassword().toCharArray()));
        userCredentials.setId(id);

        authRepository.save(userCredentials);

        return createAuthResponse(id);
    }

    public AuthResponse login(AuthRequest authRequest) {
        UserCredentials user = authRepository.findByLogin(authRequest.getLogin())
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        if (!BCrypt.verifyer().verify(authRequest.getPassword().toCharArray(),
                user.getPassword()).verified) {
            throw new BadCredentialsException("Incorrect password");
        }

        return createAuthResponse(user.getId());
    }

    public AuthResponse refresh(String tokenHeader) {
        String token = getTokenFromHeader(tokenHeader);
        if (!securityUtil.isRefreshToken(token)) throw new JwtException("Invalid token type");

        return createAuthResponse(securityUtil.getUserIdFromToken(token));
    }

    public Boolean validate(String tokenHeader) {
        return securityUtil.validateToken(getTokenFromHeader(tokenHeader));
    }

    private String getTokenFromHeader(String header) {
        if (header != null && header.startsWith("Bearer ")) return header.substring(7);
        else throw new JwtException("Invalid <Authorization> header type");
    }

    private AuthResponse createAuthResponse(UUID id) {
        return new AuthResponse(securityUtil.getAccessToken(id), securityUtil.getRefreshToken(id));
    }
}
