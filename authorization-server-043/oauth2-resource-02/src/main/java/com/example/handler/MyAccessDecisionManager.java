package com.example.handler;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.FilterInvocation;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * 权限控制
 * 判断用户角色
 */
@Component
@Slf4j
public class MyAccessDecisionManager implements AccessDecisionManager {

    private final AntPathMatcher antPathMatcher = new AntPathMatcher();

    // 这里的需要从DB加载
    private final Map<String,String> urlRoleMap = new HashMap<String,String>(){{
        put("/open/**","ROLE_ANONYMOUS");
        put("/health","ROLE_ANONYMOUS");
        put("/restart","ROLE_ADMIN");
        put("/demo","ROLE_USER");
        put("/res1","ROLE_USER");
        put("/res2","USER");
    }};

    /** 
     * @param authentication 调用方法的调用者(非空)
     * @param o 被调用的受保护对象
     * @param collection 与被调用的受保护对象关联的配置属性
     */
    @Override
    public void decide(Authentication authentication, Object o, Collection<ConfigAttribute> collection) throws AccessDeniedException, InsufficientAuthenticationException {
        //collection即是在UrlOfMenuJudgeRoleFilter中getAttributes返回的由角色组成的List<ConfigAttribute>
        //如果未登录，提示登陆
        if(authentication instanceof AnonymousAuthenticationToken){
            throw new BadCredentialsException("尚未登陆");
        }

        //1、获取URL
        FilterInvocation fi = (FilterInvocation) o;
        String url = fi.getRequestUrl();
        for(Map.Entry<String,String> entry:urlRoleMap.entrySet()){
            if(antPathMatcher.match(entry.getKey(),url)){
                String urlNeedRole = entry.getValue();
                log.info("url:{}-needRole-{}", url, urlNeedRole);
                //获得用户所授予的角色
                Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
                //判断用户的角色是否满足访问该url的角色
                for(GrantedAuthority grantedAuthority:authorities){
                    log.info("userRole-{}", grantedAuthority.getAuthority());
                    if(grantedAuthority.getAuthority().equals(urlNeedRole)){
                        return;
                    }
                }
                throw new AccessDeniedException("权限不足");
            }
        }
        log.info("white-url:{}", url);
//        //2、通过实现FilterInvocationSecurityMetadataSource接口动态获取url权限配置
//        for(ConfigAttribute configAttribute:collection){
//            //当前url所需要的角色
//            String urlNeedRole=configAttribute.getAttribute();
//            //如果URL登录即可访问就不用匹配角色
//            if("ROLE_login".equals(urlNeedRole)){
//                return;
//            }
//            //获得用户所授予的角色
//            Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
//            //判断用户的角色是否满足访问该url的角色
//            for(GrantedAuthority grantedAuthority:authorities){
//                if(grantedAuthority.getAuthority().equals(urlNeedRole)){
//                    return;
//                }
//            }
//        }
    }
 
    @Override
    public boolean supports(ConfigAttribute configAttribute) {
        return false;
    }
 
    @Override
    public boolean supports(Class<?> aClass) {
        return false;
    }
}
