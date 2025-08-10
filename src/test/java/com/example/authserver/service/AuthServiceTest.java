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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import java.util.Optional;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {
    @Mock
    private AuthRepository authRepository;

    @Mock
    private AuthMapper authMapper;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private SecurityUtil securityUtil;

    @InjectMocks
    private AuthService authService;

    private final AuthRequest authRequest = new AuthRequest();
    private final UserCredentials userCredentials = new UserCredentials();
    private AuthResponse authResponse;

    @BeforeEach
    void initialize() {
        authRequest.setLogin("login");
        authRequest.setPassword("password");

        userCredentials.setId(UUID.randomUUID());
        userCredentials.setLogin("login");
        userCredentials.setPassword("password");

        authResponse = new AuthResponse("access_token", "refresh_token");
    }

    @Test
    void testRegister() {
        when(authRepository.existsByLogin(authRequest.getLogin())).thenReturn(false);
        when(authMapper.toEntity(authRequest)).thenReturn(userCredentials);
        when(passwordEncoder.encode(authRequest.getPassword())).thenReturn("password");
        when(authRepository.save(userCredentials)).thenReturn(userCredentials);

        assertDoesNotThrow(() -> authService.register(authRequest, UUID.randomUUID()));
        verify(authRepository).save(userCredentials);
    }

    @Test
    void testRegisterLoginAlreadyExists() {
        when(authRepository.existsByLogin(authRequest.getLogin())).thenReturn(true);

        assertThrows(LoginAlreadyExistsException.class, () -> authService.register(
                authRequest, UUID.randomUUID()));
    }

    @Test
    void testLogin() {
        when(authRepository.findByLogin(authRequest.getLogin())).thenReturn(Optional.of(userCredentials));
        when(passwordEncoder.matches(authRequest.getPassword(), "password")).thenReturn(true);
        when(securityUtil.getAccessToken(userCredentials.getId())).thenReturn(authResponse.getAccessToken());
        when(securityUtil.getRefreshToken(userCredentials.getId())).thenReturn(authResponse.getRefreshToken());

        AuthResponse response = authService.login(authRequest);

        assertThat(response.getAccessToken()).isEqualTo(authResponse.getAccessToken());
        assertThat(response.getRefreshToken()).isEqualTo(authResponse.getRefreshToken());
    }

    @Test
    void testLoginUserNotFound() {
        when(authRepository.findByLogin(authRequest.getLogin())).thenReturn(Optional.empty());

        assertThrows(UserNotFoundException.class, () -> authService.login(authRequest));
    }

    @Test
    void testLoginBadCredentials() {
        when(authRepository.findByLogin(authRequest.getLogin())).thenReturn(Optional.of(userCredentials));
        when(passwordEncoder.matches(authRequest.getPassword(), "password")).thenReturn(false);

        assertThrows(BadCredentialsException.class, () -> authService.login(authRequest));
    }

    @Test
    void testRefresh() {
        when(securityUtil.isRefreshToken("refresh_token")).thenReturn(true);
        when(securityUtil.getUserIdFromToken("refresh_token")).thenReturn(userCredentials.getId());
        when(securityUtil.getAccessToken(userCredentials.getId())).thenReturn("new_access_token");
        when(securityUtil.getRefreshToken(userCredentials.getId())).thenReturn("new_refresh_token");

        AuthResponse response = authService.refresh("Bearer refresh_token");

        assertThat(response.getAccessToken()).isEqualTo("new_access_token");
        assertThat(response.getRefreshToken()).isEqualTo("new_refresh_token");
    }

    @Test
    void testRefreshInvalidToken() {
        when(securityUtil.isRefreshToken("access_token")).thenReturn(false);

        assertThrows(JwtException.class, () -> authService.refresh("Bearer access_token"));
    }

    @Test
    void testValidate() {
        when(securityUtil.validateToken("access_token")).thenReturn(true);

        assertThat(authService.validate("Bearer access_token")).isTrue();
    }

    @Test
    void testValidateInvalidToken() {
        when(securityUtil.validateToken("token")).thenReturn(false);

        assertThat(authService.validate("Bearer token")).isFalse();
    }
}
