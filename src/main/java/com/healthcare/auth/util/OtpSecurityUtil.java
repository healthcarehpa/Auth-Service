package com.healthcare.auth.util;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class OtpSecurityUtil {

    private final PasswordEncoder encoder = new BCryptPasswordEncoder();

    public String hashOtp(String otp) {
        return encoder.encode(otp);
    }

    public boolean matches(String rawOtp, String hash) {
        return encoder.matches(rawOtp, hash);
    }
}
