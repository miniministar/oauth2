package com.example.oauth2server9000.service;

import com.example.oauth2server9000.entity.User;
import com.example.oauth2server9000.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;

@Slf4j
@Service
public class UserService implements UserDetailsService {

    @Resource
    private UserRepository userRepository;
 
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.getByUsername(username);
        if(user!=null) {
            UserDetails userDetails = user.getDetail();
            return userDetails;
        }
        return null;
    }
}
