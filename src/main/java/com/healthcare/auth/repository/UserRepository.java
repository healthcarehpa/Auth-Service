package com.healthcare.auth.repository;

import com.healthcare.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);

    Optional<User> findByMobile(String mobile);

    @Query("""
        SELECT u FROM User u
        WHERE u.email = :identifier OR u.mobile = :identifier
    """)
    Optional<User> findByIdentifier(@Param("identifier") String identifier);
}

