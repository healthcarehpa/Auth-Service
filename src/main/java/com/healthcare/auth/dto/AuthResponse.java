package com.healthcare.auth.dto;

public record AuthResponse(
        int code,
        String token,
        String message,
        String status
) {}
