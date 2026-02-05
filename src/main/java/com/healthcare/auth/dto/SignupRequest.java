package com.healthcare.auth.dto;

public record SignupRequest(
        String fullName,
        String email,
        String mobile,
        String password
) {}
