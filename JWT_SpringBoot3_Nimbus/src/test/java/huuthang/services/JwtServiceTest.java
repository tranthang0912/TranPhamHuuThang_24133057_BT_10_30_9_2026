package huuthang.services;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import huuthang.entity.User;
import huuthang.exceptions.JwtValidationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Base64;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JwtServiceTest {
    private static final String SECRET = "3cfa76ef14937c1c0ea519f8fc057a80fcd04a7420f8e8bcd0a7567c272e007b";
    private static final String ISSUER = "huuthang";
    private static final String AUDIENCE = "jwt-springboot3";

    private JwtService jwtService;
    private User user;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService();
        ReflectionTestUtils.setField(jwtService, "secretKey", SECRET);
        ReflectionTestUtils.setField(jwtService, "jwtExpiration", 3_600_000L);
        ReflectionTestUtils.setField(jwtService, "jwtIssuer", ISSUER);
        ReflectionTestUtils.setField(jwtService, "jwtAudience", AUDIENCE);
        ReflectionTestUtils.setField(jwtService, "clockSkewSeconds", 60L);

        user = new User();
        user.setEmail("huuthang@example.com");
        user.setPassword("encoded-password");
        user.setFullName("Huu Thang");
        user.setImages("/images/avatar.png");
    }

    @Test
    void generateAndValidateTokenWithRequiredHeaderAndClaims() throws Exception {
        String token = jwtService.generateToken(user);
        SignedJWT signedJWT = SignedJWT.parse(token);
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

        assertEquals(JWSAlgorithm.HS256, signedJWT.getHeader().getAlgorithm());
        assertEquals(JOSEObjectType.JWT, signedJWT.getHeader().getType());
        assertEquals(user.getEmail(), claims.getSubject());
        assertEquals(ISSUER, claims.getIssuer());
        assertTrue(claims.getAudience().contains(AUDIENCE));
        assertTrue(claims.getExpirationTime().getTime() - claims.getIssueTime().getTime() >= 3_599_000L);
        assertTrue(claims.getExpirationTime().getTime() - claims.getIssueTime().getTime() <= 3_601_000L);
        assertTrue(jwtService.isTokenValid(token, user));
    }

    @Test
    void rejectTokenWithTamperedSignature() {
        String token = jwtService.generateToken(user);
        String[] parts = token.split("\\.");
        char replacement = parts[2].charAt(0) == 'A' ? 'B' : 'A';
        parts[2] = replacement + parts[2].substring(1);

        JwtValidationException exception = assertThrows(
                JwtValidationException.class,
                () -> jwtService.isTokenValid(String.join(".", parts), user)
        );
        assertEquals(JwtValidationException.Reason.INVALID_SIGNATURE, exception.getReason());
    }

    @Test
    void rejectExpiredToken() throws Exception {
        Date now = new Date();
        JWTClaimsSet claims = validClaims(now)
                .expirationTime(new Date(now.getTime() - 61_000L))
                .build();
        SignedJWT token = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.HS256).type(JOSEObjectType.JWT).build(),
                claims
        );
        token.sign(new MACSigner(Base64.getDecoder().decode(SECRET)));

        JwtValidationException exception = assertThrows(
                JwtValidationException.class,
                () -> jwtService.isTokenValid(token.serialize(), user)
        );
        assertEquals(JwtValidationException.Reason.EXPIRED, exception.getReason());
    }

    @Test
    void rejectUnsupportedAlgorithm() throws Exception {
        Date now = new Date();
        JWTClaimsSet claims = validClaims(now).build();
        SignedJWT token = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.HS384).type(JOSEObjectType.JWT).build(),
                claims
        );
        token.sign(new MACSigner(Base64.getDecoder().decode(SECRET)));

        JwtValidationException exception = assertThrows(
                JwtValidationException.class,
                () -> jwtService.isTokenValid(token.serialize(), user)
        );
        assertEquals(JwtValidationException.Reason.UNSUPPORTED_ALGORITHM, exception.getReason());
    }

    @Test
    void rejectInvalidTypeHeader() throws Exception {
        Date now = new Date();
        SignedJWT token = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.HS256).type(new JOSEObjectType("JOSE")).build(),
                validClaims(now).build()
        );
        token.sign(new MACSigner(Base64.getDecoder().decode(SECRET)));

        JwtValidationException exception = assertThrows(
                JwtValidationException.class,
                () -> jwtService.isTokenValid(token.serialize(), user)
        );
        assertEquals(JwtValidationException.Reason.INVALID_TYPE, exception.getReason());
    }

    @Test
    void rejectTokenThatIsNotValidYet() throws Exception {
        Date now = new Date();
        JWTClaimsSet claims = validClaims(now)
                .notBeforeTime(new Date(now.getTime() + 120_000L))
                .build();
        SignedJWT token = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.HS256).type(JOSEObjectType.JWT).build(),
                claims
        );
        token.sign(new MACSigner(Base64.getDecoder().decode(SECRET)));

        JwtValidationException exception = assertThrows(
                JwtValidationException.class,
                () -> jwtService.isTokenValid(token.serialize(), user)
        );
        assertEquals(JwtValidationException.Reason.NOT_YET_VALID, exception.getReason());
    }

    private JWTClaimsSet.Builder validClaims(Date now) {
        return new JWTClaimsSet.Builder()
                .subject(user.getEmail())
                .issuer(ISSUER)
                .audience(AUDIENCE)
                .issueTime(now)
                .notBeforeTime(now)
                .expirationTime(new Date(now.getTime() + 3_600_000L));
    }
}
