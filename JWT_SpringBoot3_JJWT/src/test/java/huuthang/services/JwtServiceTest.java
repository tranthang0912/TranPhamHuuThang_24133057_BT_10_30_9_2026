package huuthang.services;

import huuthang.entity.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtServiceTest {
    private static final String SECRET = "3cfa76ef14937c1c0ea519f8fc057a80fcd04a7420f8e8bcd0a7567c272e007b";

    private JwtService jwtService;
    private User user;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService();
        ReflectionTestUtils.setField(jwtService, "secretKey", SECRET);
        ReflectionTestUtils.setField(jwtService, "jwtExpiration", 3_600_000L);

        user = new User();
        user.setEmail("huuthang@example.com");
        user.setPassword("encoded-password");
        user.setFullName("Huu Thang");
        user.setImages("/images/avatar.png");
    }

    @Test
    void generateAndValidateToken() {
        String token = jwtService.generateToken(user);

        assertEquals(3, token.split("\\.").length);
        assertEquals(user.getEmail(), jwtService.extractUsername(token));
        assertTrue(jwtService.isTokenValid(token, user));
    }
}
