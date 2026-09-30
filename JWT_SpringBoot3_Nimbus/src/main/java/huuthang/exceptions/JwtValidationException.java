package huuthang.exceptions;

public class JwtValidationException extends RuntimeException {
    public enum Reason {
        INVALID_SIGNATURE,
        EXPIRED,
        MALFORMED,
        UNSUPPORTED_ALGORITHM,
        INVALID_TYPE,
        INVALID_CLAIMS,
        NOT_YET_VALID,
        SIGNING_ERROR,
        CONFIGURATION_ERROR
    }

    private final Reason reason;

    public JwtValidationException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public JwtValidationException(Reason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public Reason getReason() {
        return reason;
    }
}
