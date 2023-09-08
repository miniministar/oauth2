package com.example.property;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * <p>属性配置类</p>
 */
@Data
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {
    /*
    ======= 配置示例 ======
    # 自定义 jwt 配置
    jwt:
        cert-info:
            # 证书存放位置
            public-key-location: myKey.cer
        claims:
            # 令牌的鉴发方：即授权服务器的地址
            issuer: http://os:9000
    */
    /**
     * 证书信息（内部静态类）
     * 证书存放位置...
     */
    private CertInfo certInfo;

    /**
     * 证书声明（内部静态类）
     * 发证方...
     */
    private Claims claims;

    @Data
    public static class Claims {
        /**
         * 发证方
         */
        private String issuer;
        /**
         * 有效期
         */
        //private Integer expiresAt;
    }

    @Data
    public static class CertInfo {
        /**
         * 证书存放位置
         */
        private String publicKeyLocation;
    }
}
