package huuthang.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import huuthang.exceptions.JwtValidationException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    private static final int MIN_HMAC_KEY_BYTES = 32;

    @Value("${security.jwt.secret-key}")
    private String secretKey;

    @Value("${security.jwt.expiration-time}")
    private long jwtExpiration;

    @Value("${security.jwt.issuer}")
    private String jwtIssuer;

    @Value("${security.jwt.audience}")
    private String jwtAudience;

    @Value("${security.jwt.clock-skew-seconds:60}")
    private long clockSkewSeconds;

    public String extractUsername(String token) {
        return extractClaim(token, JWTClaimsSet::getSubject);
    }

    public <T> T extractClaim(String token, Function<JWTClaimsSet, T> claimsResolver) {
        final JWTClaimsSet claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    public long getExpirationTime() {
        return jwtExpiration;
    }

    private String buildToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            long expiration
    ) {
        validateConfiguration();
        if (expiration <= 0) {
            throw configurationError("security.jwt.expiration-time must be greater than zero");
        }

        Date now = new Date();
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder();
        extraClaims.forEach(claimsBuilder::claim);
        claimsBuilder
                .subject(userDetails.getUsername())
                .issuer(jwtIssuer)
                .audience(jwtAudience)
                .issueTime(now)
                .notBeforeTime(now)
                .expirationTime(new Date(now.getTime() + expiration));

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
                .type(JOSEObjectType.JWT)
                .build();
        SignedJWT signedJWT = new SignedJWT(header, claimsBuilder.build());

        try {
            signedJWT.sign(new MACSigner(getSignInKey()));
            return signedJWT.serialize();
        } catch (JOSEException exception) {
            throw new JwtValidationException(
                    JwtValidationException.Reason.SIGNING_ERROR,
                    "Unable to sign the JWT token",
                    exception
            );
        }
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        JWTClaimsSet claims = extractAllClaims(token);
        return claims.getSubject().equals(userDetails.getUsername());
    }

    private JWTClaimsSet extractAllClaims(String token) {
        validateConfiguration();
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            validateHeader(signedJWT.getHeader());

            if (!signedJWT.verify(new MACVerifier(getSignInKey()))) {
                throw new JwtValidationException(
                        JwtValidationException.Reason.INVALID_SIGNATURE,
                        "The JWT signature is invalid"
                );
            }

            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            validateClaims(claims);
            return claims;
        } catch (ParseException exception) {
            throw new JwtValidationException(
                    JwtValidationException.Reason.MALFORMED,
                    "The JWT token is malformed",
                    exception
            );
        } catch (JOSEException exception) {
            throw new JwtValidationException(
                    JwtValidationException.Reason.INVALID_SIGNATURE,
                    "The JWT signature is invalid",
                    exception
            );
        }
    }

    private void validateHeader(JWSHeader header) {
        if (!JWSAlgorithm.HS256.equals(header.getAlgorithm())) {
            throw new JwtValidationException(
                    JwtValidationException.Reason.UNSUPPORTED_ALGORITHM,
                    "Only HS256 JWT tokens are accepted"
            );
        }
        if (!JOSEObjectType.JWT.equals(header.getType())) {
            throw new JwtValidationException(
                    JwtValidationException.Reason.INVALID_TYPE,
                    "The JWT typ header must be JWT"
            );
        }
    }

    private void validateClaims(JWTClaimsSet claims) {
        Date now = new Date();
        long clockSkewMillis = clockSkewSeconds * 1000L;

        if (claims.getSubject() == null || claims.getSubject().isBlank()) {
            throw invalidClaims("The JWT subject is missing");
        }
        if (claims.getExpirationTime() == null) {
            throw invalidClaims("The JWT expiration time is missing");
        }
        if (now.getTime() > claims.getExpirationTime().getTime() + clockSkewMillis) {
            throw new JwtValidationException(
                    JwtValidationException.Reason.EXPIRED,
                    "The JWT token has expired"
            );
        }
        if (claims.getIssueTime() == null) {
            throw invalidClaims("The JWT issue time is missing");
        }
        if (claims.getIssueTime().getTime() > now.getTime() + clockSkewMillis) {
            throw invalidClaims("The JWT issue time is in the future");
        }
        if (claims.getNotBeforeTime() == null) {
            throw invalidClaims("The JWT not-before time is missing");
        }
        if (claims.getNotBeforeTime().getTime() > now.getTime() + clockSkewMillis) {
            throw new JwtValidationException(
                    JwtValidationException.Reason.NOT_YET_VALID,
                    "The JWT token is not valid yet"
            );
        }
        if (!jwtIssuer.equals(claims.getIssuer())) {
            throw invalidClaims("The JWT issuer is invalid");
        }
        if (claims.getAudience() == null || !claims.getAudience().contains(jwtAudience)) {
            throw invalidClaims("The JWT audience is invalid");
        }
    }

    private JwtValidationException invalidClaims(String message) {
        return new JwtValidationException(JwtValidationException.Reason.INVALID_CLAIMS, message);
    }

    private void validateConfiguration() {
        if (jwtIssuer == null || jwtIssuer.isBlank()) {
            throw configurationError("security.jwt.issuer must not be blank");
        }
        if (jwtAudience == null || jwtAudience.isBlank()) {
            throw configurationError("security.jwt.audience must not be blank");
        }
        if (clockSkewSeconds < 0) {
            throw configurationError("security.jwt.clock-skew-seconds must not be negative");
        }
    }

    private JwtValidationException configurationError(String message) {
        return new JwtValidationException(JwtValidationException.Reason.CONFIGURATION_ERROR, message);
    }

    private byte[] getSignInKey() {
        final byte[] keyBytes;
        try {
            keyBytes = Base64.getDecoder().decode(secretKey);
        } catch (IllegalArgumentException exception) {
            throw new JwtValidationException(
                    JwtValidationException.Reason.CONFIGURATION_ERROR,
                    "security.jwt.secret-key must be a valid Base64 value",
                    exception
            );
        }

        if (keyBytes.length < MIN_HMAC_KEY_BYTES) {
            throw configurationError("HS256 requires a secret key of at least 32 bytes");
        }
        return keyBytes;
    }
}
