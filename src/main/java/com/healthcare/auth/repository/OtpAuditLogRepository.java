package com.healthcare.auth.repository;

import com.healthcare.auth.entity.OtpAuditLog;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OtpAuditLogRepository extends JpaRepository<OtpAuditLog, Long> {
}
