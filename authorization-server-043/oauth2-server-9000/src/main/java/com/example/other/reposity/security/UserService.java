package com.example.other.reposity.security;

import cn.hutool.core.bean.BeanUtil;
import cn.hutool.core.lang.Assert;
import com.example.oauth2server9000.entity.SysUserDetails;
import com.example.oauth2server9000.entity.User;
import com.example.other.reposity.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.Map;

@Slf4j
@Service
public class UserService implements UserDetailsService {
 
    @Resource
    private UserRepository userRepository;
 
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findFirstByUsername(username);
        Assert.isTrue(user != null , "用户不存在");
        SysUserDetails sysUserDetails = new SysUserDetails(user);
        return sysUserDetails;
    }

    public Map<String, Object> getUserInfoMap(String username) {
        User user = userRepository.findFirstByUsername(username);
        Assert.isTrue(user != null , "用户不存在");
        Map<String, Object> map = BeanUtil.beanToMap(user);
        return map;
    }
}
