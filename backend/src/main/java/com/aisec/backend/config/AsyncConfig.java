package com.aisec.backend.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.aop.interceptor.AsyncUncaughtExceptionHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.TaskExecutor;
import org.springframework.scheduling.annotation.AsyncConfigurer;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.Executor;

/**
 * Background task executors.
 *
 * Two pools to avoid head-of-line blocking:
 *   - geoIpExecutor   — small pool dedicated to enriching alerts with country data.
 *                       Keeps the request thread free; GeoIP outages can never
 *                       slow down alert persistence.
 *   - taskExecutor    — default pool for everything else (@Async without value).
 */
@Configuration
@EnableAsync
public class AsyncConfig implements AsyncConfigurer {

    private static final Logger log = LoggerFactory.getLogger(AsyncConfig.class);

    @Override
    @Bean(name = "taskExecutor")
    public TaskExecutor getAsyncExecutor() {
        ThreadPoolTaskExecutor ex = new ThreadPoolTaskExecutor();
        ex.setCorePoolSize(4);
        ex.setMaxPoolSize(8);
        ex.setQueueCapacity(200);
        ex.setThreadNamePrefix("task-");
        ex.setWaitForTasksToCompleteOnShutdown(true);
        ex.setAwaitTerminationSeconds(15);
        ex.initialize();
        return ex;
    }

    @Bean(name = "geoIpExecutor")
    public Executor geoIpExecutor() {
        ThreadPoolTaskExecutor ex = new ThreadPoolTaskExecutor();
        ex.setCorePoolSize(2);
        ex.setMaxPoolSize(4);
        ex.setQueueCapacity(500);             // burst tolerance during alert storms
        ex.setThreadNamePrefix("geoip-");
        ex.setWaitForTasksToCompleteOnShutdown(true);
        ex.setAwaitTerminationSeconds(10);
        ex.initialize();
        return ex;
    }

    @Override
    public AsyncUncaughtExceptionHandler getAsyncUncaughtExceptionHandler() {
        return (ex, method, params) -> log.warn(
                "Uncaught async error in {}: {}", method.getName(), ex.getMessage());
    }
}
