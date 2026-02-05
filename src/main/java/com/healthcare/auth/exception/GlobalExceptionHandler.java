package com.healthcare.auth.exception;

import com.healthcare.auth.dto.AuthResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

//    @ExceptionHandler(UserNotFoundException.class)
//    public ResponseEntity<?> handleUserNotFound(UserNotFoundException ex) {
//        return ResponseEntity
//                .status(HttpStatus.NOT_FOUND)
//                .body(ex.getMessage());
//    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<AuthResponse> handleUserNotFound(
            UserNotFoundException ex) {

        return ResponseEntity
                .status(HttpStatus.NOT_FOUND)
                .body(new AuthResponse(
                        2001,
                        ex.getMessage(),
                        null, "exception"
                ));
    }

    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<AuthResponse> handleInvalidCredentials(
            InvalidCredentialsException ex) {

        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(new AuthResponse(
                        2002,
                        ex.getMessage(),
                        null,
                        "exception"
                ));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleGeneric(Exception ex) {
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body( new AuthResponse( 500,
                        "Something went wrong. Please try again.",
                        null, "excpetion"));
    }
}

