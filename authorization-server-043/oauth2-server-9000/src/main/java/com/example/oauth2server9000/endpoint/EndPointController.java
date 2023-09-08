package com.example.oauth2server9000.endpoint;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <p>用户信息接口</p>
 */
@RestController
@RequestMapping("/oauth2")
public class EndPointController {
    /**
     * 获取用户信息
     * @return
     */
    @GetMapping("/user")
    public Authentication oauth2UserInfo(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(authentication == null){
            throw new RuntimeException("无有效认证用户！");
        }
        return authentication;
    }
}
