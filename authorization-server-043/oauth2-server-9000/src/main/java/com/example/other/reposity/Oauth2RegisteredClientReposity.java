package com.example.other.reposity;

import com.example.oauth2server9000.entity.Oauth2RegisteredClient;
import org.springframework.data.jpa.repository.JpaRepository;

public interface Oauth2RegisteredClientReposity extends JpaRepository<Oauth2RegisteredClient, String> {
}
