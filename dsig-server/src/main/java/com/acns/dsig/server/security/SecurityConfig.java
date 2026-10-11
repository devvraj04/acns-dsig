package com.acns.dsig.server.security;

import com.acns.dsig.server.persistence.User;
import com.acns.dsig.server.service.UserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;

import java.time.Instant;

/**
 * Spring Security hardening configuration.
 * Configures role-based authorization, rate limiting, brute-force lockout,
 * CSRF protection, session fixation migration, and security headers.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final RateLimitFilter rateLimitFilter;
    private final LoginAttemptService loginAttemptService;

    public SecurityConfig(RateLimitFilter rateLimitFilter, LoginAttemptService loginAttemptService) {
        this.rateLimitFilter = rateLimitFilter;
        this.loginAttemptService = loginAttemptService;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(UserService userService) {
        return username -> {
            if (loginAttemptService.isBlocked(username)) {
                throw new LockedException("User account is locked due to too many failed attempts");
            }

            User user = userService.findByUsername(username)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

            if (user.getLockedUntil() != null && user.getLockedUntil().isAfter(Instant.now())) {
                throw new LockedException("User account is locked due to too many failed attempts");
            }

            return org.springframework.security.core.userdetails.User.builder()
                    .username(user.getUsername())
                    .password(user.getPasswordHash())
                    .roles(user.getRole().replace("ROLE_", ""))
                    .accountLocked(loginAttemptService.isBlocked(username))
                    .build();
        };
    }

    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        return (request, response, authentication) -> {
            if (authentication != null && authentication.getName() != null) {
                loginAttemptService.loginSucceeded(authentication.getName());
            }
            response.sendRedirect("/dashboard");
        };
    }

    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler() {
        return (request, response, exception) -> {
            String username = request.getParameter("username");
            if (username != null && !username.isBlank()) {
                String trimmed = username.trim();
                if (!(exception instanceof LockedException) && !loginAttemptService.isBlocked(trimmed)) {
                    loginAttemptService.loginFailed(trimmed);
                }
            }
            // Always redirect to generic login error page
            response.sendRedirect("/login?error");
        };
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .addFilterBefore(rateLimitFilter, UsernamePasswordAuthenticationFilter.class)
                .cors(cors -> cors.disable())
                .headers(headers -> headers
                        .contentSecurityPolicy(csp -> csp.policyDirectives(SecurityHeadersConfig.CSP_POLICY))
                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
                        .contentTypeOptions(Customizer.withDefaults())
                        .httpStrictTransportSecurity(hsts -> hsts
                                .includeSubDomains(true)
                                .maxAgeInSeconds(SecurityHeadersConfig.HSTS_MAX_AGE_SECONDS))
                        .referrerPolicy(referrer -> referrer
                                .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
                        .permissionsPolicy(permissions -> permissions
                                .policy(SecurityHeadersConfig.PERMISSIONS_POLICY))
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/css/**", "/js/**", "/images/**", "/webjars/**", "/favicon.ico").permitAll()
                        .requestMatchers("/login", "/register", "/api/health").permitAll()
                        .requestMatchers("/admin/**", "/audit/**", "/api/audit/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .defaultSuccessUrl("/dashboard", true)
                        .successHandler(authenticationSuccessHandler())
                        .failureHandler(authenticationFailureHandler())
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        .permitAll()
                )
                .sessionManagement(session -> session
                        .sessionFixation().migrateSession()
                );

        return http.build();
    }
}
