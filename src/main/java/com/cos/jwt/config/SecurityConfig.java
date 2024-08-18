package com.cos.jwt.config;


import com.cos.jwt.config.jwt.JwtAuthenticationFilter;
import com.cos.jwt.filter.MyFilter1;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final CorsConfig corsConfig;

    @Bean
    public SecurityFilterChain filerChain(HttpSecurity http) throws Exception {

        http.addFilterBefore(new MyFilter1(), BasicAuthenticationFilter.class);
        System.out.println("filterChain에서 Myfilter1 실행");
        http.csrf(CsrfConfigurer::disable);

//      세션 사용 X -> session = stateful, jwt = stateless
//		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.sessionManagement((sessionManagement) ->
                sessionManagement
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

//		http.formLogin().disable(); 로그인 폼을 사용하지 않는다.
        http.formLogin((form)->
                form.disable());

//		http.httpBasic().disable();
        http.httpBasic((basic)->
                basic.disable());

        // UsernamePasswordAuthenticationFilter.class는 security 필터중에 3번째로 시작되는 클래스이다.
        http.addFilterBefore(corsConfig.corsFilter(), UsernamePasswordAuthenticationFilter.class);
        System.out.println("corsFilter : " + corsConfig.corsFilter());

        http.addFilterBefore(new JwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

        http.authorizeHttpRequests(authorize -> authorize.requestMatchers("/api/v1/user/**").authenticated()
                .requestMatchers("/manager/**").hasAnyRole("ADMIN", "MANAGER")
                .requestMatchers("/admin/**")
                .hasAnyRole("ADMIN").anyRequest().permitAll());

        return http.build();
    }
}
