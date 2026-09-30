package huuthang.exceptions;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(Exception.class)
    public ProblemDetail handleSecurityException(Exception exception) {
        ProblemDetail errorDetail = null;
        // TODO send this stack trace to an observability tool
        exception.printStackTrace();

        if (exception instanceof DuplicateEmailException || exception instanceof DataIntegrityViolationException) {
            errorDetail = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(409), exception.getMessage());
            errorDetail.setProperty("description", "Email này đã được sử dụng.");
            return errorDetail;
        }
        if (exception instanceof IllegalArgumentException) {
            errorDetail = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(400), exception.getMessage());
            errorDetail.setProperty("description", exception.getMessage());
            return errorDetail;
        }
        if (exception instanceof BadCredentialsException) {
            errorDetail = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(401), exception.getMessage());
            errorDetail.setProperty("description", "The username or password is incorrect");
            return errorDetail;
        }
        if (exception instanceof AccountStatusException) {
            errorDetail = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(403), exception.getMessage());
            errorDetail.setProperty("description", "The account is locked");
        }
        if (exception instanceof AccessDeniedException) {
            errorDetail = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(403), exception.getMessage());
            errorDetail.setProperty("description", "You are not authorized to access this resource");
        }
        if (exception instanceof JwtValidationException jwtException) {
            int status = switch (jwtException.getReason()) {
                case SIGNING_ERROR, CONFIGURATION_ERROR -> 500;
                default -> 401;
            };
            errorDetail = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(status), exception.getMessage());
            errorDetail.setProperty("description", switch (jwtException.getReason()) {
                case INVALID_SIGNATURE -> "The JWT signature is invalid";
                case EXPIRED -> "The JWT token has expired";
                case MALFORMED -> "The JWT token is malformed";
                case UNSUPPORTED_ALGORITHM -> "The JWT signing algorithm is not allowed";
                case INVALID_TYPE -> "The JWT type header is invalid";
                case INVALID_CLAIMS -> "The JWT claims are invalid";
                case NOT_YET_VALID -> "The JWT token is not valid yet";
                case SIGNING_ERROR -> "The JWT token could not be signed";
                case CONFIGURATION_ERROR -> "The JWT configuration is invalid";
            });
        }
        if (errorDetail == null) {
            errorDetail = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(500), exception.getMessage());
            errorDetail.setProperty("description", "Unknown internal server error.");
        }
        return errorDetail;
    }
}


