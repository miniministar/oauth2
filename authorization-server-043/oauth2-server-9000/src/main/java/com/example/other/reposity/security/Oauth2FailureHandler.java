package com.example.other.reposity.security;

import com.alibaba.fastjson2.JSON;
import com.example.oauth2server9000.entity.Result;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class Oauth2FailureHandler implements AuthenticationFailureHandler {
 
 
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        String message;
        if (exception instanceof OAuth2AuthenticationException) {
            OAuth2AuthenticationException exception1 = (OAuth2AuthenticationException) exception;
            OAuth2Error error = exception1.getError();
            message = "认证信息错误：" + error.getErrorCode() + error.getDescription();
        } else {
            message = exception.getMessage();
        }
 
        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(HttpStatus.OK.value());
        Result result = new Result(401, message);
        response.getWriter().write(JSON.toJSONString(result));
        response.getWriter().flush();
 
    }
}
