package com.example.oauth2server9000.config;

import cn.hutool.core.map.MapUtil;
import com.example.oauth2server9000.entity.User;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.*;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.stream.Collectors;

@Configuration
public class JWTokenConfig {

    /**
     生成jks和cer
     参考：Java Keytool生成数字证书/.cer/.p12文件，https://blog.csdn.net/devil_bye/article/details/82759140

     打开cmd，切换至目标目录
     创建密钥库
     # keystore格式
     # 别名：mykey
     keytool -genkeypair -alias mykey -keyalg RSA -keysize 2048 -validity 365 -keystore mykey.keystore
     # 参数解释：
     # storepass  keystore文件存储密码，不加这个参数会在后面要求你输入密码
     # keypass  私钥加解密密码
     # alias  实体别名(包括证书私钥)
     # dname  证书个人信息
     # keyalg  采用公钥算法，默认是DSA，这里采用RSA
     # keysize  密钥长度(DSA算法对应的默认算法是sha1withDSA，不支持2048长度，此时需指定RSA)
     # validity  有效期
     # keystore  指定keystore文件储存位置

     # jks格式
     # 别名：myjks
     keytool -genkeypair -alias myjks -keyalg RSA -validity 365 -keystore myjks.jks

     查看密钥库
     # keystore格式
     keytool -v -list -keystore myjks.keystore
     # jks格式
     keytool -v -list -keystore myjks.jks

     导出本地证书cer
     # keystore格式导出
     keytool -exportcert -keystore  myjks.keystore -file myjks.cer -alias myjks
     # 参数解释：
     # -export  表示证书导出操作
     # -keystore  指定秘钥库文件
     # -file  指定导出文件路径
     # -storepass  输入密码
     # -rfc  指定以Base64编码格式输出

     # jks格式导出
     keytool -exportcert -keystore  myjks.jks -file myjks.cer -alias myjks

     打印cer证书
     Keytool -printcert -file myjks.cer
     复制生成的 myjks.jks、myjks.cer 到授权服务器的资源路径下；jks 用于生成token时加密，cer用于解析token时解密
     */

    /**
     * jwt解码器
     * 客户端认证授权后，需要访问user信息，解码器可以从令牌中解析出user信息
     * @return
     */
    @SneakyThrows
    @Bean
    JwtDecoder jwtDecoder() {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("x.509");
        // 读取cer公钥证书来配置解码器
        ClassPathResource resource = new ClassPathResource("myjks.cer"); //Keytool生成数字证书
        Certificate certificate = certificateFactory.generateCertificate(resource.getInputStream());
        RSAPublicKey publicKey = (RSAPublicKey) certificate.getPublicKey();
        return NimbusJwtDecoder.withPublicKey(publicKey).build();
    }

    /**
     * 加载jwk资源
     * 用于生成令牌
     * @return
     */
    @SneakyThrows
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        // 证书的路径
        String path = "myjks.jks";
        // 证书别名
        String alias = "myjks";
        // keystore 密码
        String pass = "123456";

        ClassPathResource resource = new ClassPathResource(path);
        KeyStore jks = KeyStore.getInstance("jks");
        char[] pin = pass.toCharArray();
        jks.load(resource.getInputStream(), pin);
        RSAKey rsaKey = RSAKey.load(jks, alias, pin);

        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }


//    /**
//     * 生成jwk资源,com.nimbusds.jose.jwk.source.JWKSource用于签署访问令牌的实例。
//     * @return
//     */
//    @Bean
//    public JWKSource<SecurityContext> jwkSource() {
//        KeyPair keyPair = generateRsaKey();
//        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
//        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
//        RSAKey rsaKey = new RSAKey.Builder(publicKey)
//                .privateKey(privateKey)
//                .keyID(UUID.randomUUID().toString())
//                .build();
//        JWKSet jwkSet = new JWKSet(rsaKey);
//        return new ImmutableJWKSet<>(jwkSet);
//    }

    /**
     * 生成密钥对,启动时生成的带有密钥的实例java.security.KeyPair用于创建JWKSource上述内容
     * @return
     */
    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        }
        catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

//    @Bean
//    public JwtEncoder jwtEncoder() {
//        return new NimbusJwtEncoder(jwkSource());
//    }

//    @Bean
//    public OAuth2TokenGenerator<?> tokenGenerator() {
//        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder());
//        jwtGenerator.setJwtCustomizer(jwtCustomizer());
//        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
//        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
//        return new DelegatingOAuth2TokenGenerator(jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
//    }

    @Autowired
    PasswordEncoder passwordEncoder;

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
            JoseHeader.Builder headers = context.getHeaders();
            JwtClaimsSet.Builder claims = context.getClaims();
            Map<String, Object> map = claims.build().getClaims();
            if (context.getTokenType().getValue().equals(OidcParameterNames.ID_TOKEN)) {
                // Customize headers/claims for access_token
//                headers.header("customerHeader", "这是一个自定义header");
//                claims.claim("customerClaim", "这是一个自定义Claim");
                String username = (String) map.get("sub");
//                String sql = "select avatar, url from oauth_demo.oauth2_user where username = ?";
//                UserEntity userEntity = jdbcTemplate.queryForObject(sql, new BeanPropertyRowMapper<>(UserEntity.class), username);
                User.UserBuilder builder = User.builder();
//                PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
                builder.id(1).deptId(1).gender(1).status(1).nickname("user")
                        .dataScope(1).roles(Arrays.asList("USER"))
                        .password(passwordEncoder.encode("password"));
                User user = builder.build();
                Optional<User> userEntityOptional = Optional.ofNullable(user);
                if (userEntityOptional.isPresent()) {
                    claims.claim("roles", userEntityOptional.get().getRoles());
                }
            }

            Object principal = context.getPrincipal().getPrincipal();
            // 检查登录用户信息是不是UserDetails，排除掉没有用户参与的流程
            if (principal instanceof UserDetails) {
                UserDetails user = (UserDetails) principal;
                // 获取申请的scopes
                Set<String> scopes = context.getAuthorizedScopes();
                // 获取用户的权限
                Collection<? extends GrantedAuthority> authorities = user.getAuthorities();
                // 提取权限并转为字符串
                Set<String> authoritySet = Optional.ofNullable(authorities).orElse(Collections.emptyList()).stream()
                        // 获取权限字符串
                        .map(GrantedAuthority::getAuthority)
                        // 去重
                        .collect(Collectors.toSet());

                // 合并scope与用户信息
                authoritySet.addAll(scopes);

                // 将权限信息放入jwt的claims中（也可以生成一个以指定字符分割的字符串放入）
                claims.claim("authorities", authoritySet);
                // 放入其它自定内容
                // 角色、头像...
            }
        };
    }
}
