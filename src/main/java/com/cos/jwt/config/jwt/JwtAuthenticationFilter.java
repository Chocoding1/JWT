package com.cos.jwt.config.jwt;

import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;

/**
 * 스프링 시큐리티의 여러 필터 중 UsernamePasswordAuthenticationFilter가 있다.
 * 해당 필터는 username과 password를 가지고 /login 요청(POST)이 들어왔을 때 실행된다.
 */
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JwtProperties jwtProperties;

    /**
     * /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter: 로그인 시도 중");


        try {
/*
            BufferedReader br = request.getReader();

            String input = null;
            while ((input = br.readLine()) != null) {
                System.out.println(input);
            }
*/
            ObjectMapper om = new ObjectMapper();
            // 1. username, password 받아서 토큰 생성
            User user = om.readValue(request.getInputStream(), User.class);
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // 2. 생성한 토큰으로 로그인 시도. authenticationManager로 로그인 시도를 하면
            // PrincipalDetailsService의 loadUserByUsername() 메서드가 실행된다.
            /**
             * 이 코드가 실행될 때, PrincipalDetailsService의 loadUserByUsername() 메서드가 실행된다.
             * AuthenticationManager에 토큰을 넣어서 던지면 인증을 해준다.
             * 인증이 되면, Authentication을 반환한다.(로그인이 되었다는 뜻)
             * 이 Authentication 객체는 밑에서 return으로 반환하면 시큐리티 세션 영역에 저장된다. (Spring Security 코드 참고)
             */
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            // 3. loadUserByUsername()의 반환값인 PrincipalDetails를 세션에 담는다.
            // 위 과정은 SecurityConfig에서 권한 관리가 필요할 때만 하면 됨. 특정 role의 회원만 접근할 수 있는 페이지가 있다던지 등
            // 만약 권한 관리가 필요 없다면 세션에 담는 과정은 없어도 된다.
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("로그인 완료됨. username = " + principalDetails.getUser().getUsername());

            // 4. JWT를 만들어서 응답해주면 끝
            /**
             * authentication 객체가 session 영역에 저장됨. 저장 방법이 return하는 것임
             * return의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는 것
             * 굳이 JWT를 사용하면서 세션을 만들 이유는 없다. 단지 권한 처리때문에 세션을 넣어준 것
             */
            return authentication;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * attemptAuthentication 함수 실행 후, 인증이 정상적으로 되면 다음으로 실행되는 함수
     * 여기서 JWT를 만들어서 request 요청한 사용자에게 response
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("로그인 완료 -> successfulAuthentication 실행");

        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();



        SecretKey secretKey = Keys.hmacShaKeyFor(jwtProperties.getSecretKey().getBytes(StandardCharsets.UTF_8));

        String jwt = Jwts.builder()
                .subject("cos토큰")
                .expiration(new Date(System.currentTimeMillis() + (60000 * 10)))
                .claim("id", principalDetails.getUser().getId())
                .claim("username", principalDetails.getUsername())
                .signWith(secretKey)
                .compact();

        response.addHeader("Authorization", "Bearer " + jwt);

//        super.successfulAuthentication(request, response, chain, authResult);
    }
}
