package com.aisec.backend.repository;

import com.aisec.backend.entity.AppSetting;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppSettingRepository extends JpaRepository<AppSetting, Long> {
}
