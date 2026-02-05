package com.healthcare.auth.service;

import com.healthcare.auth.entity.OtpAuditLog;
import com.healthcare.auth.entity.User;
import com.healthcare.auth.entity.UserOtp;
import com.healthcare.auth.exception.InvalidCredentialsException;
import com.healthcare.auth.exception.UserNotFoundException;
import com.healthcare.auth.repository.OtpAuditLogRepository;
import com.healthcare.auth.repository.UserOtpRepository;
import com.healthcare.auth.util.OtpSecurityUtil;
import jakarta.transaction.Transactional;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;

@Service
@Transactional
public class OtpService {

    private static final int OTP_EXPIRY_MINUTES = 5;
    private static final int MAX_RETRIES = 3;

    private final UserOtpRepository otpRepo;
    private final OtpAuditLogRepository auditRepo;
    private final OtpSecurityUtil otpUtil;

    public OtpService(
            UserOtpRepository otpRepo,
            OtpAuditLogRepository auditRepo,
            OtpSecurityUtil otpUtil
    ) {
        this.otpRepo = otpRepo;
        this.auditRepo = auditRepo;
        this.otpUtil = otpUtil;
    }

    // SEND OTP
    public void sendOtp(String identifier, String ip, String agent) {

        String otp = generateOtp();
        String hash = otpUtil.hashOtp(otp);

        UserOtp entity = new UserOtp();
        entity.setIdentifier(identifier);
        entity.setOtpHash(hash);
        entity.setExpiresAt(LocalDateTime.now().plusMinutes(OTP_EXPIRY_MINUTES));
        entity.setRetryCount(0);
        entity.setMaxRetries(MAX_RETRIES);
        entity.setUsed(false);
        entity.setCreatedAt(LocalDateTime.now());

        otpRepo.save(entity);
        audit(identifier, "SENT", ip, agent);

        // DEV ONLY
        System.out.println("DEV OTP for " + identifier + " = " + otp);

        // PROD → send via SMS / Email
    }

    // VERIFY OTP
    public void verifyOtp(String identifier, String otp, String ip, String agent) {

        UserOtp entity = otpRepo.findTopByIdentifierAndUsedFalseOrderByCreatedAtDesc(identifier)
                .orElseThrow(() -> new InvalidCredentialsException("OTP not found"));

        if (entity.isUsed()) {
            audit(identifier, "FAILED", ip, agent);
            throw new InvalidCredentialsException("OTP already used");
        }

        if (entity.getRetryCount() >= entity.getMaxRetries()) {
            audit(identifier, "FAILED", ip, agent);
            throw new InvalidCredentialsException("OTP retry limit exceeded");
        }

        if (entity.getExpiresAt().isBefore(LocalDateTime.now())) {
            audit(identifier, "EXPIRED", ip, agent);
            throw new InvalidCredentialsException("OTP expired");
        }

        if (!otpUtil.matches(otp, entity.getOtpHash())) {
            entity.setRetryCount(entity.getRetryCount() + 1);
            otpRepo.save(entity);

            audit(identifier, "FAILED", ip, agent);
            throw new InvalidCredentialsException("Invalid OTP");
        }

        entity.setUsed(true);
        otpRepo.save(entity);

        audit(identifier, "VERIFIED", ip, agent);
    }

    private void audit(String identifier, String event, String ip, String agent) {
        OtpAuditLog log = new OtpAuditLog();
        log.setIdentifier(identifier);
        log.setEventType(event);
        log.setIpAddress(ip);
        log.setUserAgent(agent);
        log.setCreatedAt(LocalDateTime.now());
        auditRepo.save(log);
    }

    private String generateOtp() {
        return String.valueOf(new SecureRandom().nextInt(900000) + 100000);
    }
}
