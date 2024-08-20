package com.cos.jwt.config.jwt;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;

import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.dto.LoginRequestDto;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;

import javax.crypto.SecretKey;

import static org.springframework.security.config.Elements.JWT;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // 인증 요청 시 실행
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {

        System.out.println("JwtAuthenticationFilter: 진입");

        // Request에서 username과 password를 추출
        ObjectMapper om = new ObjectMapper();
        LoginRequestDto loginRequestDto = null;
        try {
            loginRequestDto = om.readValue(request.getInputStream(), LoginRequestDto.class);
        } catch (IOException e) {
            e.printStackTrace();
        }

        System.out.println("JwtAuthenticationFilter: " + loginRequestDto);

        // UsernamePasswordAuthenticationToken 생성
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(
                        loginRequestDto.getUsername(),
                        loginRequestDto.getPassword());

        System.out.println("JwtAuthenticationFilter: 토큰 생성 완료");

        // authenticate() 호출 시 인증 프로세스가 실행됨
        System.out.println("authenticationManager 실행");

        // 여기서 PrincipalDetailsService의 loadUserByUserName메서드 실행
        Authentication authentication = authenticationManager.authenticate(authenticationToken);
        System.out.println("authenticationManager 실행 종료");

        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("Authentication: " + principalDetails.getUser().getUsername());

        return authentication;
    }

    // 인증 성공 시 JWT 토큰 생성
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {

        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        SecretKey secretKey = Keys.hmacShaKeyFor(JwtProperties.SECRET.getBytes(StandardCharsets.UTF_8));

        String jwtToken = Jwts.builder()
                .setSubject(principalDetails.getUsername())
                .setExpiration(new Date(System.currentTimeMillis() + JwtProperties.EXPIRATION_TIME))
                .claim("id", principalDetails.getUser().getId())
                .claim("username", principalDetails.getUser().getUsername())
                .signWith(secretKey)
                .compact();

        response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX + jwtToken);
    }
}
