package com.example.oauth2server9000.entity;

import lombok.Data;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import java.time.Instant;

@Data
@Entity
@Table(name = "oauth2_registered_client")
public class Oauth2RegisteredClient {

    @Column(name = "id")
    @Id
    private String id;

    @Column(name = "client_id")
    private String clientId;


    @Column(name = "client_id_issued_at")
    private Instant clientIdIssuedAt;

    @Column(name = "client_secret" )
    private String clientSecret;

    @Column(name = "client_secret_expires_at" )
    private Instant clientSecretExpiresAt;

    @Column(name = "client_name" )
    private String clientName;

    @Column(name = "client_authentication_methods" )
    private String clientAuthenticationMethods;

    @Column(name = "authorization_grant_types" )
    private String authorizationGrantTypes;

    @Column(name = "redirect_uris" )
    private String redirectUris;

    @Column(name = "scopes" )
    private String scopes;

    @Column(name = "client_settings" )
    private String clientSettings;

    @Column(name = "token_settings" )
    private String tokenSettings;
}
