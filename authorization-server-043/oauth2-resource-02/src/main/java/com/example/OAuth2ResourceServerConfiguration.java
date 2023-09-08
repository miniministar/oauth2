package com.example;

import cn.hutool.core.collection.CollectionUtil;
import cn.hutool.core.convert.Convert;
import cn.hutool.json.JSONUtil;
import com.example.handler.*;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;

import java.util.Arrays;
import java.util.List;

/**
 * <p>资源服务器配置</p>
 * 当解码器JwtDecoder存在时生效
 * proxyBeanMethods = false 每次调用都创建新的对象
 * @version 1.0
 */
//@ConditionalOnBean(JwtDecoder.class)
@Configuration(proxyBeanMethods = false)
@Slf4j
public class OAuth2ResourceServerConfiguration {

    @Setter
    private List<String> ignoreUrls;
    @Autowired
    private AccessDeniedHandler accessDeniedHandler;
    @Autowired
    private AuthenticationEntryPoint authenticationEntryPoint;
    /**
     * 资源管理器配置
     *
     * @param http the http
     * @return the security filter chain
     * @throws Exception the exception
     */
    @Bean
    SecurityFilterChain jwtSecurityFilterChain(HttpSecurity http) throws Exception {
//        // 拒绝访问处理器 401
//        SimpleAccessDeniedHandler accessDeniedHandler = new SimpleAccessDeniedHandler();
//        // 认证失败处理器 403
//        SimpleAuthenticationEntryPoint authenticationEntryPoint = new SimpleAuthenticationEntryPoint();

        if (CollectionUtil.isEmpty(ignoreUrls)) {
            ignoreUrls = Arrays.asList("/webjars/**", "/doc.html", "/swagger-resources/**", "/v2/api-docs");
        }

        log.info("whitelist path:{}", JSONUtil.toJsonStr(ignoreUrls));

        http
                //使用jwt，不需要使用csrf拦截器
                .csrf().disable()
                // security的session生成策略改为security不主动创建session即STALELESS
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers(Convert.toStrArray(ignoreUrls)).permitAll() //放行相关请求和资源*/
                // 对 /res1 的请求，需要 SCOPE_read 权限
//                .antMatchers("/res1").hasAnyAuthority("SCOPE_read","SCOPE_all")
//                .antMatchers("/res2").hasAnyAuthority("SCOPE_write1","SCOPE_all")
//        要实现动态鉴权，可以从两方面着手：
//        自定义SecurityMetadataSource，实现从数据库加载ConfigAttribute
//        另外就是可以自定义accessDecisionManager，官方的UnanimousBased其实足够使用，并且他是基于AccessDecisionVoter来实现权限认证的，因此我们只需要自定义一个AccessDecisionVoter就可以了
//                .withObjectPostProcessor(getObjectPostProcessor())//动态权限配置
                // 自定义FilterInvocationSecurityMetadataSource
                // 1、获取某个受保护的安全对象object的所需要的权限信息,是一组ConfigAttribute对象的集合
                // 2、通过accessDecisionManager再去校验ConfigAttribute对象和访问对象的权限
//                .accessDecisionManager(accessDecisionManager())
                .withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {
                    @Override
                    public <O extends FilterSecurityInterceptor> O postProcess(
                            O fsi) {
//                        fsi.setSecurityMetadataSource(mySecurityMetadataSource(fsi.getSecurityMetadataSource()));
                        fsi.setAccessDecisionManager(new MyAccessDecisionManager());
                        return fsi;
                    }
                })
//                .addFilterBefore(getJwtAuthenticationTokenFilter(), UsernamePasswordAuthenticationFilter.class)//添加登陆过滤器
                // 自定义accessDecisionManager
                // 其余请求都需要认证
                .anyRequest().authenticated()

        ;

        http.oauth2ResourceServer()
                .jwt()
                .jwtAuthenticationConverter(jwtAuthenticationConverter())
                .and()
                .authenticationEntryPoint(authenticationEntryPoint)
                .accessDeniedHandler(accessDeniedHandler)
        ;

//        http
//                // 异常处理
//                .exceptionHandling(exceptionConfigurer -> exceptionConfigurer
//                        // 拒绝访问
//                        .accessDeniedHandler(accessDeniedHandler)
//                        // 认证失败
//                        .authenticationEntryPoint(authenticationEntryPoint)
//                )
//                // 资源服务
//                .oauth2ResourceServer(resourceServer -> resourceServer
//                                .jwt()
//                                .jwtAuthenticationConverter(jwtAuthenticationConverter())
////                        .jwtAuthenticationConverter(jwtAuthenticationConverter())
//                                .and()
//                                .accessDeniedHandler(accessDeniedHandler)
//                                .authenticationEntryPoint(authenticationEntryPoint)
//                );
        return http.build();
    }

    /**
     * 动态鉴权 方式一：
     * 自定义FilterInvocationSecurityMetadataSource
     * @param filterInvocationSecurityMetadataSource
     * @return
     */
//    @Bean
    public AppFilterInvocationSecurityMetadataSource mySecurityMetadataSource(FilterInvocationSecurityMetadataSource filterInvocationSecurityMetadataSource) {
        AppFilterInvocationSecurityMetadataSource securityMetadataSource = new AppFilterInvocationSecurityMetadataSource(filterInvocationSecurityMetadataSource);
        return securityMetadataSource;
    }

//    @Bean
    public AccessDecisionManager accessDecisionManager() {
        List<AccessDecisionVoter<? extends Object>> decisionVoters
                = Arrays.asList(
                new WebExpressionVoter(),
                // new RoleVoter(),
                new RoleBasedVoter(),
                new AuthenticatedVoter());
        return new UnanimousBased(decisionVoters);
    }
    /**
     * JWT个性化解析
     *
     * @return
     */
//    @Bean
    JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
//        如果不按照规范  解析权限集合Authorities 就需要自定义key
        jwtGrantedAuthoritiesConverter.setAuthoritiesClaimName("authorities");
//        OAuth2 默认前缀是 SCOPE_     Spring Security 是 ROLE_
        jwtGrantedAuthoritiesConverter.setAuthorityPrefix("");
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);
        // 用户名 可以放sub
        jwtAuthenticationConverter.setPrincipalClaimName(JwtClaimNames.SUB);
        return jwtAuthenticationConverter;
    }
}
