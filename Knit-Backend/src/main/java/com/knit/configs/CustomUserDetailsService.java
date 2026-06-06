package com.knit.configs;

import com.knit.entities.User;
import com.knit.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email)
            throws UsernameNotFoundException {

        User user = userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new UsernameNotFoundException(
                                "User not found with email: " + email
                        ));

        return new org.springframework.security.core.userdetails.User(
                user.getEmail(),
                user.getPassword(),
                List.of()
        );
    }
}