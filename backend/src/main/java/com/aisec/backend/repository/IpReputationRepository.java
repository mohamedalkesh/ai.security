package com.aisec.backend.repository;

import com.aisec.backend.entity.IpReputation;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface IpReputationRepository extends JpaRepository<IpReputation, Long> {
    Optional<IpReputation> findByIpAddress(String ipAddress);
}
