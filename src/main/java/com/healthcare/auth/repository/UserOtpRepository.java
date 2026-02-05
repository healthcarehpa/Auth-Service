package com.healthcare.auth.repository;

import com.healthcare.auth.entity.UserOtp;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserOtpRepository extends JpaRepository<UserOtp, Long> {

    Optional<UserOtp> findTopByIdentifierAndUsedFalseOrderByCreatedAtDesc(String identifier);
}
