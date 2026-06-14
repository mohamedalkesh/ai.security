package com.aisec.backend.repository;

import com.aisec.backend.entity.PasswordResetToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {

    Optional<PasswordResetToken> findByToken(String token);

    Optional<PasswordResetToken> findByEmailAndToken(String email, String token);

    @Modifying
    @Transactional
    @Query("DELETE FROM PasswordResetToken t WHERE t.email = :email")
    void deleteAllByEmail(String email);

    @Modifying
    @Transactional
    @Query("DELETE FROM PasswordResetToken t WHERE t.expiresAt < :now")
    void deleteExpired(Instant now);
}
