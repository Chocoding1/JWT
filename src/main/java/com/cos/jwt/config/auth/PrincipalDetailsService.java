package com.cos.jwt.config.auth;

import com.cos.jwt.repository.UserRepository;
import com.cos.jwt.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * http://localhost:8080/login으로 로그인 요청 시 해당 서비스 실행
 * 그러나! SecurityFilterChain에서 formlogin 설정을 꺼놨기 때문에
 * 해당 /login으로 요청이 들어와도 UserDetailsService 타입의 loadUserByUsername 메서드가 실행되지 않는다.
 * 그래서 강제로 loadUserByUsername을 실행하는 필터를 하나 만들어야 한다.(여기서는 JwtAuthenticationFilter)
 */
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User userEntity = userRepository.findByUsername(username);

        return new PrincipalDetails(userEntity);
    }
}
