package com.cos.jwt.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter1 implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        // 토큰 : cos 이걸 id와 pw가 일치할때 로그인이 완료가 되면 토큰을 만들어주고 이걸 응답을 해준다.
        // 요청할 때 마다 header에 Autorization에 value값으로 토큰을 가지고 오면?
        // 토큰이 넘어오고 이 토큰이 내가 만든 토큰인지 검증만 하면 된다.->(RSA, HS256)
        if (req.getMethod().equals("POST")) {
            System.out.println("POST");
            String headerAuth = req.getHeader("Authorization");
            System.out.println(headerAuth);
            System.out.println("필터1");

            if (headerAuth.equals("cos")) {
                filterChain.doFilter(req, res);
            } else {
                PrintWriter out = res.getWriter();
                out.println("인증 안됨");
            }


        }
    }
}
