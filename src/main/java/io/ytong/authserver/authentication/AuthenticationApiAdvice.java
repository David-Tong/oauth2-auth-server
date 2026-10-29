package io.ytong.authserver.authentication;

import java.io.IOException;

import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import jakarta.servlet.http.HttpServletResponse;

@RestControllerAdvice(assignableTypes = AuthenticationController.class)
public class AuthenticationApiAdvice {

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public void missingParameter(HttpServletResponse response) throws IOException {
        ApiError.write(response, 400, "invalid_request");
    }

    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public void unsupportedMediaType(HttpServletResponse response) throws IOException {
        ApiError.write(response, 415, "unsupported_media_type");
    }
}
