package com.aisec.backend.repository;

import com.aisec.backend.entity.UserAccount;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<UserAccount, Long> {
    Optional<UserAccount> findByUsername(String username);
    Optional<UserAccount> findByEmail(String email);
    boolean existsByUsername(String username);
    boolean existsByEmail(String email);

    @Query("SELECT u FROM UserAccount u WHERE (:orgId IS NULL AND u.organization IS NULL) OR u.organization.id = :orgId")
    List<UserAccount> findByOrg(@Param("orgId") Long orgId);
}
