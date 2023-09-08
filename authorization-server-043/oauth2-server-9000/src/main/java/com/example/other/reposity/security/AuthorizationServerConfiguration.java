package com.example.other.reposity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.function.Function;

/**
 * <p>授权服务配置</p>
 */
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfiguration {
    /**
     * 授权配置
     * // @Order 表示加载优先级；HIGHEST_PRECEDENCE为最高优先级
     *
     * @param http
     * @return
     * @throws Exception
     */
    @Autowired
    private CacheRegisteredClientRepository clientRepository;
    @Autowired
    private UserService userService;

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        // 定义授权服务配置器
        OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer<>();
        http.apply(authorizationServerConfigurer);
        authorizationServerConfigurer.registeredClientRepository(clientRepository);

        // 获取授权服务器相关的请求端点
        RequestMatcher authorizationServerEndpointsMatcher =
                authorizationServerConfigurer.getEndpointsMatcher();

        //自定义用户映射器
        Function<OidcUserInfoAuthenticationContext, OidcUserInfo> userInfoMapper = (context) -> {
            OidcUserInfoAuthenticationToken authentication = context.getAuthentication();
            JwtAuthenticationToken principal = (JwtAuthenticationToken) authentication.getPrincipal();
            return new OidcUserInfo(userService.getUserInfoMap(principal.getName()));
        };

        authorizationServerConfigurer
                //设置客户端授权中失败的handler处理
                .clientAuthentication((auth) -> auth.errorResponseHandler(new Oauth2FailureHandler())
                        .authenticationSuccessHandler(new Oauth2SuccessHandler())
                )
                //token 相关配置 如  /oauth2/token接口
                .tokenEndpoint((token) -> token.errorResponseHandler(new Oauth2FailureHandler()))
                // Enable OpenID Connect 1.0， 包括用户信息等
                //.oidc(Customizer.withDefaults());
                .oidc(oidc ->
                    oidc.userInfoEndpoint(userInfoEndpoint ->
                        userInfoEndpoint
                                .userInfoMapper(userInfoMapper)

                    )
                );

        http

                // 拦截对 授权服务器 相关端点的请求
                .requestMatcher(authorizationServerEndpointsMatcher)
                // 拦载到的请求需要认证确认（登录）
                .authorizeRequests()
                // 其余所有请求都要认证
                .anyRequest().authenticated()
             .and()
                // 忽略掉相关端点的csrf（跨站请求）：对授权端点的访问可以是跨站的
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers(authorizationServerEndpointsMatcher))

                //.and()
                // 表单登录
                .formLogin()
              .and()
                .logout();
        return http.build();
    }

    /**
     * 令牌的发放记录
     *
     * @param jdbcTemplate               操作数据库
     * @param registeredClientRepository 客户端仓库
     * @return 授权服务
     */
    @Bean
    public OAuth2AuthorizationService auth2AuthorizationService(
            JdbcTemplate jdbcTemplate,
            @Qualifier("jdbcRegisteredClientRepository") RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    /**
     * 把资源拥有者授权确认操作保存到数据库
     * 资源拥有者（Resource Owner）对客户端的授权记录
     *
     * @param jdbcTemplate               操作数据库
     * @param registeredClientRepository 客户端仓库
     * @return
     */
    @Bean
    public OAuth2AuthorizationConsentService auth2AuthorizationConsentService(
            JdbcTemplate jdbcTemplate,
            @Qualifier("jdbcRegisteredClientRepository") RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }


//    /**
//     * 加载jwk资源
//     * 用于生成令牌
//     * @return
//     */
//    @SneakyThrows
//    @Bean
//    public JWKSource<SecurityContext> jwkSource() {
//        // 证书的路径
//        String path = "myjks.jks";
//        // 证书别名
//        String alias = "myjks";
//        // keystore 密码
//        String pass = "123456";
//
//        ClassPathResource resource = new ClassPathResource(path);
//        KeyStore jks = KeyStore.getInstance("jks");
//        char[] pin = pass.toCharArray();
//        jks.load(resource.getInputStream(), pin);
//        RSAKey rsaKey = RSAKey.load(jks, alias, pin);
//
//        JWKSet jwkSet = new JWKSet(rsaKey);
//        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
//    }

    /**
     * <p>授权服务器元信息配置</p>
     * <p>
     * 授权服务器本身也提供了一个配置工具来配置其元信息，大多数都使用默认配置即可，唯一需要配置的其实只有授权服务器的地址issuer
     * 在生产中这个地方应该配置为域名
     *
     * @return
     */
    @Bean
    public ProviderSettings providerSettings() {
        return ProviderSettings.builder().issuer("http://localhost:9000").build();
    }
}
