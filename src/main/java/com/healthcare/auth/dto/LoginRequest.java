package com.healthcare.auth.dto;

public record LoginRequest(
        String identifier, // email OR mobile
        String password
) {}
