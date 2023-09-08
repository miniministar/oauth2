package com.example.other.reposity;

import com.example.oauth2server9000.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Integer> {
 
    User findFirstByUsername(String username);
}
