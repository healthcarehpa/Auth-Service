package com.healthcare.auth.service;

import com.healthcare.auth.dto.AuthResponse;
import com.healthcare.auth.dto.LoginRequest;
import com.healthcare.auth.dto.OtpVerifyRequest;
import com.healthcare.auth.dto.SignupRequest;
import com.healthcare.auth.entity.User;
import com.healthcare.auth.exception.InvalidCredentialsException;
import com.healthcare.auth.exception.UserNotFoundException;
import com.healthcare.auth.repository.UserRepository;
import com.healthcare.auth.security.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final UserRepository repo;
    private final PasswordEncoder encoder;
    private final JwtUtil jwtUtil;
    private final OtpService otpService;

    public AuthService(
            UserRepository repo,
            PasswordEncoder encoder,
            JwtUtil jwtUtil,
            OtpService otpService
    ) {
        this.repo = repo;
        this.encoder = encoder;
        this.jwtUtil = jwtUtil;
        this.otpService = otpService;
    }

    // SIGNUP
    public void signup(SignupRequest req) {

        if (repo.findByEmail(req.email()).isPresent()) {
            throw new InvalidCredentialsException("This email is already registered.");
        }

        if (repo.findByMobile(req.mobile()).isPresent()) {
            throw new InvalidCredentialsException("This phone number is already registered.");
        }

        User user = new User();
        user.setFullName(req.fullName());
        user.setEmail(req.email());
        user.setMobile(req.mobile());
        user.setPassword(encoder.encode(req.password()));

        repo.save(user);
    }

    public AuthResponse login(LoginRequest req) {

        User user = repo.findByIdentifier(req.identifier())
                .orElseThrow(() ->
                        new UserNotFoundException("No account found with provided email or mobile")
                );

        if (!encoder.matches(req.password(), user.getPassword())) {
            throw new InvalidCredentialsException("Incorrect password");
        }

        String token = jwtUtil.generateTokenwRSA(user);
        return new AuthResponse(200, token, "Login successful", "success");
    }

    // SEND OTP
    public void sendOtp(String identifier, HttpServletRequest request) {

        User user = repo.findByIdentifier(identifier)
                .orElseThrow(() ->
                        new UserNotFoundException(
                                "No account found with provided email or mobile"
                        )
                );

        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");

        // Delegate ALL OTP responsibility to OtpService
        otpService.sendOtp(
                identifier,
                ipAddress,
                userAgent
        );
    }


    // VERIFY OTP LOGIN
    public AuthResponse verifyOtpLogin(OtpVerifyRequest req,
                                       HttpServletRequest httpReq) {

        otpService.verifyOtp(
                req.identifier(),
                req.otp(),
                httpReq.getRemoteAddr(),
                httpReq.getHeader("User-Agent")
        );

        User user = repo.findByIdentifier(req.identifier())
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        return new AuthResponse(
                200,
                jwtUtil.generateTokenwRSA(user),
                "OTP Verified successful",
                "success"
        );
    }

}
