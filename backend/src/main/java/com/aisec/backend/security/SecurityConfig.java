package com.aisec.backend.security;

import com.aisec.backend.config.AppProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtAuthFilter jwtFilter;
    private final RateLimitFilter rateLimitFilter;
    private final CustomUserDetailsService uds;
    private final AppProperties props;

    public SecurityConfig(JwtAuthFilter jwtFilter,
                          RateLimitFilter rateLimitFilter,
                          CustomUserDetailsService uds,
                          AppProperties props) {
        this.jwtFilter = jwtFilter;
        this.rateLimitFilter = rateLimitFilter;
        this.uds = uds;
        this.props = props;
    }

    @Bean
    public PasswordEncoder passwordEncoder() { return new BCryptPasswordEncoder(); }

    @Bean
    public DaoAuthenticationProvider authProvider() {
        DaoAuthenticationProvider p = new DaoAuthenticationProvider();
        p.setUserDetailsService(uds);
        p.setPasswordEncoder(passwordEncoder());
        return p;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration cfg) throws Exception {
        return cfg.getAuthenticationManager();
    }

    @Bean
    public CorsConfigurationSource corsSource() {
        CorsConfiguration c = new CorsConfiguration();

        // Explicit origins from config (production), e.g. https://app.example.com
        String[] configured = props.getCors().originsArray();
        java.util.Set<String> origins = new java.util.LinkedHashSet<>(Arrays.asList(configured));
        origins.add("null"); // file:// and IDE proxy origins
        if (!origins.isEmpty()) {
            c.setAllowedOrigins(new java.util.ArrayList<>(origins));
        }

        // Origin patterns — accept any port on localhost / 127.0.0.1 for dev
        // and IDE browser-preview proxies (random ports like :34067).
        c.setAllowedOriginPatterns(List.of(
                "http://localhost:*",
                "http://127.0.0.1:*"
        ));

        c.setAllowedMethods(List.of("GET","POST","PUT","PATCH","DELETE","OPTIONS"));
        c.setAllowedHeaders(List.of("Authorization","Content-Type","X-Requested-With","Accept"));
        c.setExposedHeaders(List.of("X-Total-Count","X-Request-Id"));
        c.setAllowCredentials(true);
        c.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource src = new UrlBasedCorsConfigurationSource();
        src.registerCorsConfiguration("/**", c);
        return src;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .cors(c -> c.configurationSource(corsSource()))
            .csrf(c -> c.disable())
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(a -> a
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .requestMatchers("/api/auth/**").permitAll()
                .requestMatchers("/api/company-request").permitAll()
                .requestMatchers("/api/health", "/actuator/**").permitAll()
                .requestMatchers("/ws/**").permitAll()
                .requestMatchers(HttpMethod.DELETE, "/api/users/**").hasAnyRole("ADMIN", "ORG_ADMIN")
                .requestMatchers(HttpMethod.POST,   "/api/users/**").hasAnyRole("ADMIN", "ORG_ADMIN")
                .requestMatchers(HttpMethod.PUT,    "/api/users/**").hasAnyRole("ADMIN", "ORG_ADMIN")
                .requestMatchers("/api/users/**").hasAnyRole("ADMIN", "ORG_ADMIN", "ANALYST")
                .requestMatchers("/api/organizations/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .authenticationProvider(authProvider())
            .addFilterBefore(rateLimitFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
