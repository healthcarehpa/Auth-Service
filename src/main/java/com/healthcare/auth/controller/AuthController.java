package com.healthcare.auth.controller;


import com.healthcare.auth.dto.*;
import com.healthcare.auth.service.AuthService;
import com.healthcare.auth.service.OtpService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService service;
    private final OtpService otpService;

    public AuthController(AuthService service,
                          OtpService otpService   ) {
        this.service = service;
        this.otpService=otpService;
    }

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody SignupRequest request) {
        service.signup(request);
        return ResponseEntity.ok(new AuthResponse(200, "", "Registration successful. You can now log in.", "success"));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest request) {
        return ResponseEntity.ok(service.login(request));

    }

    @PostMapping("/otp/send")
    public ResponseEntity<?> sendOtp(@RequestBody OtpRequest req,
                                     HttpServletRequest httpReq) {
        otpService.sendOtp(
                req.identifier(),
                httpReq.getRemoteAddr(),
                httpReq.getHeader("User-Agent")
        );

        return ResponseEntity.ok(new AuthResponse(200, "", "OTP sent successfully", "success"));
    }

    @PostMapping("/otp/verify")
    public ResponseEntity<AuthResponse> verifyOtp(
            @RequestBody OtpVerifyRequest req,
            HttpServletRequest httpReq) {

        return ResponseEntity.ok(
                service.verifyOtpLogin(req, httpReq)
        );
    }


}
