package org.example.expert.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtUtil jwtUtil;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // JWT 방식이라 csrf 불필요
                .csrf(csrf -> csrf.disable())
                // formLogin 비활성화
                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable())
                // 세션 비활성화
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // URL별 접근 권한 설정
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/**").permitAll()       // 로그인/회원가입은 누구나 접근 가능
                        .requestMatchers("/admin/**").hasRole("ADMIN") // /admin은 ADMIN만 접근 가능
                        .anyRequest().authenticated()                   // 나머지는 로그인한 사람만
                )
                // JwtSecurityFilter를 Security 기본 필터 앞에 등록
                .addFilterBefore(new JwtAuthenticationFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

}
