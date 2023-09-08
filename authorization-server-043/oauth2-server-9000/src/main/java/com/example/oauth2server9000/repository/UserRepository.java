package com.example.oauth2server9000.repository;

import com.example.oauth2server9000.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.core.userdetails.UserDetails;

public interface UserRepository extends JpaRepository<User, Integer> {
    User getByUsername(String username);
}
