package com.healthcare.auth.dto;

public record OtpRequest(
        String identifier // email OR mobile
) {}

