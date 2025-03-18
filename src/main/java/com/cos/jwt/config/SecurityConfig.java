package com.cos.jwt.config;

import com.cos.jwt.config.jwt.JwtAuthenticationFilter;
import com.cos.jwt.filter.MyFilter1;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsFilter corsFilter;
    private final UserDetailsService userDetailsService; // UserDetailsService 주입 필요!


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
        http.addFilterBefore(new MyFilter1(), SecurityContextHolderFilter.class);
        /**
         * JWT(JSON Web Token) 기반 인증을 사용할 때는 CSRF 보호가 필요 X
         * CSRF는 세션 기반 인증(쿠키 기반)에서 주로 문제가 되는데, JWT는 쿠키를 사용하지 않으므로 비활성화
         */
        http.csrf(CsrfConfigurer::disable);
        http
                .addFilter(corsFilter)
                .addFilter(new JwtAuthenticationFilter(authenticationManager))
                /**
                 * 세션을 사용하지 않도록 설정
                 * JWT를 사용하면 세션을 저장할 필요가 없기 때문에 STATELESS(무상태)로 설정
                 */
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                /**
                 * 기본적인 로그인 폼 기능 비활성화
                 * JWT를 사용하므로 로그인 시 폼을 사용하지 않기 때문
                 */
                .formLogin(FormLoginConfigurer::disable)
                /**
                 * HTTP Basic 인증은 Authorization 헤더에 ID/PW를 담아 요청하는 방식
                 * 보안이 취약하므로 JWT를 사용하면 필요 X
                 * JWT는 Authorization 헤더에 JWT를 담아 요청하는 방식
                 */
                .httpBasic(HttpBasicConfigurer::disable)
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/api/v1/user/**").hasAnyRole("USER", "MANAGER", "ADMIN")
                        .requestMatchers("/api/v1/manager/**").hasAnyRole("MANAGER", "ADMIN")
                        .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
                        .anyRequest().permitAll()

                );
        return http.build();
    }
}
