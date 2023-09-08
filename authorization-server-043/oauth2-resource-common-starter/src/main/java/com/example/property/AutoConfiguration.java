package com.example.property;

import com.example.handler.SimpleAccessDeniedHandler;
import com.example.handler.SimpleAuthenticationEntryPoint;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

import javax.annotation.Resource;

/**
 * <p>资源服务器配置</p>
 * 当解码器JwtDecoder存在时生效
 */
//@ConditionalOnBean(JwtDecoder.class)
@EnableConfigurationProperties(AuthProperty.class)
@Configuration
public class AutoConfiguration {
    @Resource
    private AuthProperty authProperty;
    /**
     * 资源管理器配置
     *
     * @param http the http
     * @return the security filter chain
     * @throws Exception the exception
     */
    @Bean
    SecurityFilterChain jwtSecurityFilterChain(HttpSecurity http) throws Exception {
        // 拒绝访问处理器 401
        SimpleAccessDeniedHandler accessDeniedHandler = new SimpleAccessDeniedHandler();
        // 认证失败处理器 403
        SimpleAuthenticationEntryPoint authenticationEntryPoint = new SimpleAuthenticationEntryPoint();

        return http
                // security的session生成策略改为security不主动创建session即STALELESS
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
                // 允许【pc客户端】或【其它微服务】访问
                .authorizeRequests()
                //.antMatchers("/**").hasAnyAuthority("SCOPE_client_pc","SCOPE_micro_service")
                // 从配置文件中读取权限信息
                .antMatchers("/**").hasAnyAuthority(authProperty.getAllAuth())
                // 其余请求都需要认证
                .anyRequest().authenticated()
             .and()
                // 异常处理
                .exceptionHandling(exceptionConfigurer -> exceptionConfigurer
                        // 拒绝访问
                        .accessDeniedHandler(accessDeniedHandler)
                        // 认证失败
                        .authenticationEntryPoint(authenticationEntryPoint)
                )
                // 资源服务
                .oauth2ResourceServer(resourceServer -> resourceServer
                        .accessDeniedHandler(accessDeniedHandler)
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .jwt()
                )
                .build();
    }


    /**
     * JWT个性化解析
     *
     * @return
     */
    @Bean
    JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
//        如果不按照规范  解析权限集合Authorities 就需要自定义key
//        jwtGrantedAuthoritiesConverter.setAuthoritiesClaimName("scopes");
//        OAuth2 默认前缀是 SCOPE_     Spring Security 是 ROLE_
//        jwtGrantedAuthoritiesConverter.setAuthorityPrefix("");
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);
        // 用户名 可以放sub
        jwtAuthenticationConverter.setPrincipalClaimName(JwtClaimNames.SUB);
        return jwtAuthenticationConverter;
    }

    /**
     * 开放一些端点的访问控制
     * 不需要认证就可以访问的端口
     * @return
     */
    @Bean
    WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring().antMatchers(
                "/actuator/**"
        );
    }
}
