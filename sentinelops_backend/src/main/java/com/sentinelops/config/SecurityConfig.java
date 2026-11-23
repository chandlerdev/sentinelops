package com.sentinelops.config;

import com.sentinelops.security.JwtAuthFilter;
import com.sentinelops.security.RateLimitFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
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

/**
 * Central security policy.
 *
 * Hardening applied here:
 *  - Stateless JWT auth (no server session, no CSRF-able cookie).
 *  - BCrypt password hashing (strength 12).
 *  - Deny-by-default: every route requires authentication unless explicitly public.
 *  - Role-based route rules + method-level security (@PreAuthorize) in services.
 *  - Strict CORS allowlist from configuration.
 *  - Security response headers (HSTS, frame-deny, no-sniff, referrer policy, CSP).
 *  - Per-IP rate limiting before authentication.
 *  - Actuator restricted to ADMIN.
 */
@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    private final AppProperties props;

    public SecurityConfig(AppProperties props) {
        this.props = props;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration cfg) throws Exception {
        return cfg.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                           JwtAuthFilter jwtAuthFilter,
                                           RateLimitFilter rateLimitFilter) throws Exception {
        http
            // Stateless API: disable CSRF token machinery (no cookies used for auth).
            .csrf(AbstractHttpConfigurer::disable)
            .cors(cors -> cors.configurationSource(corsSource()))
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.POST, "/api/auth/login").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/health").permitAll()
                .requestMatchers("/actuator/health").permitAll()
                .requestMatchers("/actuator/**").hasRole("ADMIN")
                // Administration
                .requestMatchers("/api/users/**").hasRole("ADMIN")
                .requestMatchers(HttpMethod.PUT, "/api/settings/**").hasRole("ADMIN")
                .requestMatchers(HttpMethod.GET, "/api/settings/**").hasAnyRole("ADMIN", "MANAGER")
                .requestMatchers("/api/audit/**").hasAnyRole("ADMIN", "MANAGER")
                // Clients and engagements: managers/admins create; everyone authenticated reads (object-level checks in services)
                .requestMatchers(HttpMethod.POST, "/api/clients", "/api/engagements").hasAnyRole("MANAGER", "ADMIN")
                // Targets and ownership verification
                .requestMatchers(HttpMethod.POST, "/api/engagements/*/targets/*/verification/manual").hasAnyRole("MANAGER", "ADMIN")
                .requestMatchers(HttpMethod.POST, "/api/engagements/*/targets/**").hasAnyRole("TESTER", "MANAGER", "ADMIN")
                .requestMatchers(HttpMethod.POST, "/api/engagements/*/targets").hasAnyRole("TESTER", "MANAGER", "ADMIN")
                // Authorization workflow: tester proposes/submits; manager/admin decides
                .requestMatchers(HttpMethod.POST, "/api/authorizations/*/approve", "/api/authorizations/*/reject",
                        "/api/authorizations/*/revoke").hasAnyRole("MANAGER", "ADMIN")
                .requestMatchers(HttpMethod.POST, "/api/engagements/*/authorizations", "/api/authorizations/*/submit")
                        .hasAnyRole("TESTER", "MANAGER", "ADMIN")
                // Starting a scan is tester/manager only.
                .requestMatchers(HttpMethod.POST, "/api/engagements/*/scan", "/api/scans/*/stop")
                        .hasAnyRole("TESTER", "MANAGER", "ADMIN")
                // Phase 3-5: findings workflow, schedules, scan credentials, OpenAPI. Services enforce object-level rules
                // (a CLIENT may only change status of confirmed findings of their own client).
                .requestMatchers(HttpMethod.POST, "/api/findings/*/validate", "/api/findings/*/retest",
                        "/api/engagements/*/schedules").hasAnyRole("TESTER", "MANAGER", "ADMIN")
                .requestMatchers(HttpMethod.PUT, "/api/schedules/*/enabled", "/api/engagements/*/targets/*/credential",
                        "/api/engagements/*/targets/*/openapi").hasAnyRole("TESTER", "MANAGER", "ADMIN")
                .requestMatchers(HttpMethod.DELETE, "/api/schedules/*", "/api/engagements/*/targets/*/credential")
                        .hasAnyRole("TESTER", "MANAGER", "ADMIN")
                .requestMatchers(HttpMethod.GET, "/api/engagements/*/targets/*/credential", "/api/engagements/*/schedules")
                        .hasAnyRole("TESTER", "MANAGER", "ADMIN")
                .anyRequest().authenticated()
            )
            .headers(h -> h
                .httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(31536000))
                .frameOptions(fo -> fo.deny())
                .contentTypeOptions(c -> {})
                .referrerPolicy(r -> r.policy(
                    org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER))
                .addHeaderWriter((req, res) -> {
                    res.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
                    res.setHeader("Permissions-Policy", "geolocation=(), camera=(), microphone=()");
                })
            )
            .addFilterBefore(rateLimitFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    private CorsConfigurationSource corsSource() {
        CorsConfiguration cfg = new CorsConfiguration();
        cfg.setAllowedOrigins(Arrays.stream(props.getSecurity().getCorsAllowedOrigins().split(","))
                .map(String::trim).toList());
        cfg.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        cfg.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        cfg.setAllowCredentials(false);
        cfg.setMaxAge(3600L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", cfg);
        return source;
    }
}
