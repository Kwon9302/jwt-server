package com.cos.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration // Cross Origin Resource Sharing
public class CorsConfig {
    @Bean
    public CorsFilter corsFilter() {
        System.out.println("CORS Filter 실행");
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.addAllowedOriginPattern("*"); // 모든 ip에 응답 허용
        config.addAllowedHeader("*"); // 모든 Headerd에 응답 허용
        config.addAllowedMethod("*"); // 모든 post,get,put,delete에 응답 허

        source.registerCorsConfiguration("/api/**", config);
        return new CorsFilter(source);
    }

}
