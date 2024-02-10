package com.example.userservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer.FrameOptionsConfig;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        return http
                .csrf(CsrfConfigurer<HttpSecurity>::disable)
                .headers(it -> it.frameOptions(FrameOptionsConfig::disable))
                .authorizeHttpRequests(it -> it
                        .requestMatchers(new AntPathRequestMatcher("/users/**")).permitAll()
                        .anyRequest().permitAll()
                )
                .build();
    }

}
