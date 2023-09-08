package com.example.other.reposity.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;

import java.time.Duration;
import java.util.UUID;

@Configuration
public class RegisteredClientConfig {

    /**
     * 注册客户端
     *
     * @param jdbcTemplate 操作数据库
     * @return 客户端仓库
     */
    @Bean("jdbcRegisteredClientRepository")
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        // ---------- 1、检查当前客户端是否已注册
        // 操作数据库对象
        JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);

        /*
         客户端在数据库中的几个记录字段的说明
         ------------------------------------------
         id：仅表示客户端在数据库中的这个记录
         client_id：唯一标示客户端；请求token时，以此作为客户端的账号
         client_name：客户端的名称，可以省略
         client_secret：密码
         */
        String clientId_1 = "my_client";
        // 查询客户端是否存在
        RegisteredClient registeredClient_1 = registeredClientRepository.findByClientId(clientId_1);

        // ---------- 2、添加客户端
        // 数据库中没有
        if (registeredClient_1 == null) {
            registeredClient_1 = this.createRegisteredClientAuthorizationCode(clientId_1);
            registeredClientRepository.save(registeredClient_1);
        }

        // ---------- 3、返回客户端仓库
        return registeredClientRepository;
    }

    /**
     * 定义客户端（令牌申请方式：授权码模式）
     *
     * @param clientId 客户端ID
     * @return
     */
    private RegisteredClient createRegisteredClientAuthorizationCode(final String clientId) {
        // JWT（Json Web Token）的配置项：TTL、是否复用refrechToken等等
        TokenSettings tokenSettings = TokenSettings.builder()
                // 令牌存活时间：2小时
                .accessTokenTimeToLive(Duration.ofHours(2))
                // 令牌可以刷新，重新获取
                .reuseRefreshTokens(true)
                // 刷新时间：30天（30天内当令牌过期时，可以用刷新令牌重新申请新令牌，不需要再认证）
                .refreshTokenTimeToLive(Duration.ofDays(30))
                .build();
        // 客户端相关配置
        ClientSettings clientSettings = ClientSettings.builder()
                // 是否需要用户授权确认
                .requireAuthorizationConsent(false)
                .build();

        return RegisteredClient
                // 客户端ID和密码
                .withId(UUID.randomUUID().toString())
                //.withId(id)
                .clientId(clientId)
                //.clientSecret("{noop}123456")
                .clientSecret(PasswordEncoderFactories.createDelegatingPasswordEncoder().encode("secret"))
                // 客户端名称：可省略
                .clientName("messaging-client")
                // 授权方法
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                // 授权模式
                // ---- 【授权码模式】
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                // ---------- 刷新令牌（授权码模式）
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                /* 回调地址：
                 * 授权服务器向当前客户端响应时调用下面地址；
                 * 不在此列的地址将被拒绝；
                 * 只能使用IP或域名，不能使用localhost
                 */
                .redirectUri("http://127.0.0.1:8000/login/oauth2/code/myClient")
                .redirectUri("http://127.0.0.1:8000")
                // 授权范围（当前客户端的授权范围）
                .scope("read")
                .scope("write")
                // JWT（Json Web Token）配置项
                .tokenSettings(tokenSettings)
                // 客户端配置项
                .clientSettings(clientSettings)
                .build();
    }
}
