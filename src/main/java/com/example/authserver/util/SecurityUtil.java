package com.example.authserver.util;

import com.example.authserver.exception.InvalidSecurityParametersException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

@Component
public class SecurityUtil {
    private static final String ACCESS_TOKEN = "access_token";
    private static final String REFRESH_TOKEN = "refresh_token";
    private static final String USER_ID = "userId";

    @Value("${ACCESS_EXPIRATION}")
    private int accessTokenExpiration;

    @Value("${REFRESH_EXPIRATION}")
    private int refreshTokenExpiration;

    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    public SecurityUtil(@Value("${PUBLIC_KEY}") String pbKey, @Value("${PRIVATE_KEY}") String prKey) {
        try {
            privateKey = KeyFactory.getInstance("RSA").generatePrivate(
                    new PKCS8EncodedKeySpec(Base64.getDecoder().decode(prKey)));
            
            publicKey = KeyFactory.getInstance("RSA").generatePublic(
                    new X509EncodedKeySpec(Base64.getDecoder().decode(pbKey)));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new InvalidSecurityParametersException(e.getMessage());
        }
    }

    public String getAccessToken(UUID userId) {
        return Jwts.builder()
                .subject(ACCESS_TOKEN)
                .claim(USER_ID, userId.toString())
                .issuedAt(new Date())
                .expiration(Date.from(Instant.now().plusSeconds(accessTokenExpiration)))
                .signWith(privateKey, Jwts.SIG.RS256)
                .compact();
    }

    public String getRefreshToken(UUID userId) {
        return Jwts.builder()
                .subject(REFRESH_TOKEN)
                .claim(USER_ID, userId.toString())
                .issuedAt(new Date())
                .expiration(Date.from(Instant.now().plusSeconds(refreshTokenExpiration)))
                .signWith(privateKey, Jwts.SIG.RS256)
                .compact();
    }

    public boolean validateToken(String token){
        try {
            Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public UUID getUserIdFromToken(String token){
        Claims claims = Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return UUID.fromString(claims.get(USER_ID, String.class));
    }

    public boolean isRefreshToken(String token){
        return REFRESH_TOKEN.equals(Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject());
    }
}
