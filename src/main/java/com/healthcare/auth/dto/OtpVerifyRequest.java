package com.healthcare.auth.dto;

public record OtpVerifyRequest(
        String identifier,
        String otp
) {}


