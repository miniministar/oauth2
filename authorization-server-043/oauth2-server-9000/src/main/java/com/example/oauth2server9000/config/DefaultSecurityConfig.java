package com.example.oauth2server9000.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * <p>授权服务器安全策略</p>
 */
@EnableWebSecurity(debug = true)
@Slf4j
public class DefaultSecurityConfig {
    /**
     * 配置 请求授权
     *
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        // 配置 请求授权
        http.authorizeRequests(authorizeRequests ->
                // 任何请求都需要认证（不对未登录用户开放）
                authorizeRequests.anyRequest().authenticated()
            )
                // 表单登录
                .formLogin()
            .and()
                .logout()
                .and().csrf().disable()
                .oauth2ResourceServer()
                .jwt()

        ;
        return http.build();
    }

    /**
     * 模拟用户
     *
     * @return
     */
//    @Bean
//    UserDetailsService users() {
//        UserDetails user = User.builder()
//                .username("user")
//                .password("password")
//                .passwordEncoder(PasswordEncoderFactories.createDelegatingPasswordEncoder()::encode)
//                .roles("USER")
//                //.authorities("SCOPE_userinfo")
//                .build();
//        return new InMemoryUserDetailsManager(user);
//    }


    /**
     * 开放一些端点的访问控制
     * 不需要认证就可以访问的端口
     * @return
     */
    @Bean
    WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring().antMatchers("/actuator/health", "/actuator/info", "/favicon.ico", "/resources/**", "/error");
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        String encode = bCryptPasswordEncoder.encode("123456");
        log.info("password: {}", encode);
        return bCryptPasswordEncoder;
    }


}
