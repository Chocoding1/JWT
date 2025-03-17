package com.cos.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource(); // 여러 URL 경로에 대해 각기 다른 CORS 설정을 적용할 수 있는 객체
        CorsConfiguration config = new CorsConfiguration(); // CORS 정책을 설정하는 객체(허용할 출처, 헤더, HTTP 메서드 등을 정의)
        config.setAllowCredentials(true); // 내 서버가 응답을 할 때, json을 자바스크립트에서 처리하도록 설정
        config.addAllowedOrigin("*"); // 모든 ip에 응답을 허용
        config.addAllowedHeader("*"); // 모든 header에 응답을 허용
        config.addAllowedMethod("*"); // 모든 POST, GET, PUT, DELETE, FETCH에 요청을 허용
        source.registerCorsConfiguration("/api/**", config); // /api/** 경로에 대해 config에서 설정한 CORS 정책을 적용
        return new CorsFilter(source);
    }
}
