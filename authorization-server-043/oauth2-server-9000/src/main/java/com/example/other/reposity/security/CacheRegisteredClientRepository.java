
package com.example.other.reposity.security;

import cn.hutool.core.lang.Assert;
import cn.hutool.core.util.StrUtil;
import com.alibaba.fastjson2.JSON;
import com.example.oauth2server9000.constant.Constant;
import com.example.oauth2server9000.entity.Oauth2RegisteredClient;
import com.example.other.reposity.Oauth2RegisteredClientReposity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

@Component
public class CacheRegisteredClientRepository implements RegisteredClientRepository {
    @Autowired
    private RedisTemplate redisTemplate;
    @Resource
    private Oauth2RegisteredClientReposity clientReposity;

    @Resource
    @Qualifier("jdbcRegisteredClientRepository")
    private JdbcRegisteredClientRepository jdbcRegisteredClientRepository;

    @PostConstruct
    public void init() {
        List<Oauth2RegisteredClient> all = clientReposity.findAll();
//        List<RegisteredClient> clientList = convertRegisteredClient(all);
        all.forEach(i->{
            redisTemplate.opsForValue().set(Constant.OAUTH2_CLIENT_KEY + i.getClientId(), JSON.toJSONString(i));
            redisTemplate.opsForValue().set(Constant.OAUTH2_CLIENT_KEY + i.getId(), JSON.toJSONString(i));
        });
    }
    private List<RegisteredClient> convertRegisteredClient(List<Oauth2RegisteredClient> all) {
        List<RegisteredClient> list = new ArrayList<>();
        if( all != null) {
            all.forEach(i-> {
                RegisteredClient client = jdbcRegisteredClientRepository.findById(i.getId());
                list.add(client);
            });
        }
        return list;
    }

    private RegisteredClient convertRegisteredClientOne(Oauth2RegisteredClient entity) {
        RegisteredClient.Builder builder = RegisteredClient.withId(entity.getId());
        builder
                .clientId(entity.getClientId())
                .clientIdIssuedAt(entity.getClientIdIssuedAt())
                .clientSecret(entity.getClientSecret())
                .clientSecretExpiresAt(entity.getClientSecretExpiresAt())
                .clientName(entity.getClientName())
                .redirectUri(entity.getRedirectUris());

        if(StrUtil.isNotBlank(entity.getClientAuthenticationMethods())) {
            List<String> list = Arrays.asList(entity.getClientAuthenticationMethods().split(","));
            list.forEach(i->{
                ClientAuthenticationMethod authenticationMethod = new ClientAuthenticationMethod(i);
                builder.clientAuthenticationMethod(authenticationMethod);
            });
        }
        if(StrUtil.isNotBlank(entity.getAuthorizationGrantTypes())) {
            List<String> list = Arrays.asList(entity.getAuthorizationGrantTypes().split(","));
            list.forEach(i->{
                builder.authorizationGrantType(new AuthorizationGrantType(i));
            });
        }
        if(StrUtil.isNotBlank(entity.getScopes())) {
            List<String> list = Arrays.asList(entity.getScopes().split(","));
            list.forEach(i->{
                builder.scope(i);
            });
        }
        if(StrUtil.isNotBlank(entity.getClientSettings())) {
            ClientSettings.Builder builder1 = ClientSettings.builder();
            Map map = JSON.parseObject(entity.getClientSettings(), Map.class);
            map.forEach((k,v)->{
                String k1 = (String) k;
                builder1.setting(k1, v);
            });
            ClientSettings build = builder1.build();
            builder.clientSettings(build);
        }
        if(StrUtil.isNotBlank(entity.getTokenSettings())) {
            TokenSettings.Builder builder1 = TokenSettings.builder();
            Map map = JSON.parseObject(entity.getTokenSettings(), Map.class);
            map.forEach((k,v)->{
                String k1 = (String) k;
                builder1.setting(k1, v);
            });
            TokenSettings build = builder1.build();
            builder.tokenSettings(build);
        }

        return builder.build();
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        //do nothing
    }

    @Override
    public RegisteredClient findById(String id) {
        String s = (String) redisTemplate.opsForValue().get(Constant.OAUTH2_CLIENT_KEY + id);
        Assert.isTrue(StrUtil.isNotEmpty(s), "不存在的clientId：" + id);
        RegisteredClient client = JSON.parseObject(s, RegisteredClient.class);
        return client;
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        String s = (String) redisTemplate.opsForValue().get(Constant.OAUTH2_CLIENT_KEY + clientId);
        Assert.isTrue(StrUtil.isNotEmpty(s), "不存在的clientId：" + clientId);
        Oauth2RegisteredClient client = JSON.parseObject(s, Oauth2RegisteredClient.class);
        RegisteredClient client1 = convertRegisteredClientOne(client);
        return client1;
    }
}
