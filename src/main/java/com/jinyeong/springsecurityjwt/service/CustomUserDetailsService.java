package com.jinyeong.springsecurityjwt.service;

import com.jinyeong.springsecurityjwt.domain.CustomUserDetails;
import com.jinyeong.springsecurityjwt.entity.UserEntity;
import com.jinyeong.springsecurityjwt.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // DB 조회
        UserEntity userData = userRepository.findByUsername(username);

        if (userData != null) {
            // UserDetails에 담아서 return 하면 AuthenticationManager가 검증 함
            return new CustomUserDetails(userData);
        }

        return null;
    }
}
