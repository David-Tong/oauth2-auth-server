package io.ytong.authserver.authentication;

import java.io.IOException;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;

public class ApiError extends RuntimeException {
    private final HttpStatus status;
    private final String code;
    public ApiError(HttpStatus status, String code) { super(code); this.status = status; this.code = code; }
    public HttpStatus status() { return status; }
    public String code() { return code; }
    public static void write(HttpServletResponse response, int status, String code) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.setHeader("Cache-Control", "no-store");
        response.getWriter().write("{\"error\":\"" + code + "\",\"message\":\"Request could not be completed\"}");
    }
}
