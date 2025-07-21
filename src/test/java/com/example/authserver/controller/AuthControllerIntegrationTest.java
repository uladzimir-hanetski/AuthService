package com.example.authserver.controller;

import com.example.authserver.dto.AuthRequest;
import com.example.authserver.dto.AuthResponse;
import com.example.authserver.entity.UserCredentials;
import com.example.authserver.exception.ErrorResponse;
import com.example.authserver.repository.AuthRepository;
import com.example.authserver.util.SecurityUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import java.util.UUID;
import static org.assertj.core.api.Assertions.assertThat;

@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuthControllerIntegrationTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15-alpine")
            .withDatabaseName("test")
            .withUsername("test")
            .withPassword("test");

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
    }

    @Autowired
    TestRestTemplate restTemplate;

    @Autowired
    AuthRepository authRepository;

    @Autowired
    SecurityUtil securityUtil;

    private final AuthRequest authRequest = new AuthRequest();
    private final UserCredentials userCredentials = new UserCredentials();

    @BeforeEach
    void initialize() {
        authRepository.deleteAll();

        authRequest.setLogin("login");
        authRequest.setPassword("password");

        userCredentials.setLogin("login");
        userCredentials.setPassword("password");
    }

    @Test
    void testRegister() {
        ResponseEntity<Void> response = restTemplate.postForEntity("/v1/auth/register", authRequest, Void.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(authRepository.existsByLogin(authRequest.getLogin())).isTrue();
    }

    @Test
    void testRegisterInvalidLogin() {
        AuthRequest request = new AuthRequest();
        authRequest.setLogin("lo");
        authRequest.setPassword("password");

        ResponseEntity<Void> response = restTemplate.postForEntity("/v1/auth/register", request, Void.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void testRegisterLoginAlreadyExists() {
        authRepository.save(userCredentials);

        ResponseEntity<ErrorResponse> response = restTemplate.postForEntity("/v1/auth/register", authRequest, ErrorResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
    }

    @Test
    void testLogin() {
        restTemplate.postForEntity("/v1/auth/register", authRequest, Void.class);

        ResponseEntity<AuthResponse> response = restTemplate.postForEntity("/v1/auth/login", authRequest, AuthResponse.class);

        assertThat(response.getBody().getAccessToken()).isNotNull();
        assertThat(response.getBody().getRefreshToken()).isNotNull();
    }

    @Test
    void testLoginBadCredentials() {
        AuthRequest request = new AuthRequest();
        authRequest.setLogin("login");
        authRequest.setPassword("not_a_valid_password");

        authRepository.save(userCredentials);

        ResponseEntity<ErrorResponse> response = restTemplate.postForEntity("/v1/auth/login", request, ErrorResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void testLoginUserNotFound() {
        ResponseEntity<ErrorResponse> response = restTemplate.postForEntity("/v1/auth/login", authRequest, ErrorResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void testRefresh() {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(securityUtil.getRefreshToken(UUID.randomUUID()));
        HttpEntity<Void> entity = new HttpEntity<>(headers);

        ResponseEntity<AuthResponse> response = restTemplate.postForEntity("/v1/auth/refresh", entity, AuthResponse.class);

        assertThat(response.getBody().getAccessToken()).isNotNull();
        assertThat(response.getBody().getRefreshToken()).isNotNull();
    }

    @Test
    void testRefreshInvalidToken() {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(securityUtil.getAccessToken(UUID.randomUUID()));
        HttpEntity<Void> entity = new HttpEntity<>(headers);

        ResponseEntity<ErrorResponse> response = restTemplate.postForEntity("/v1/auth/refresh", entity, ErrorResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void testRefreshNotAuthenticated() {
        ResponseEntity<ErrorResponse> response = restTemplate.postForEntity("/v1/auth/refresh", null, ErrorResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void testValidate() {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(securityUtil.getAccessToken(UUID.randomUUID()));
        HttpEntity<Void> entity = new HttpEntity<>(headers);

        ResponseEntity<Boolean> response = restTemplate.exchange("/v1/auth/validate", HttpMethod.GET, entity, Boolean.class);

        assertThat(response.getBody()).isTrue();
    }

    @Test
    void testValidateMissingHeader() {
        ResponseEntity<ErrorResponse> response = restTemplate.exchange("/v1/auth/validate", HttpMethod.GET, null, ErrorResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }
}
