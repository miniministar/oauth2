package com.example.property;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.CollectionUtils;

import java.util.Set;

/**
 * <p>权限属性类</p>
 */
@Data
@ConfigurationProperties(prefix = "resource-auth")
public final class AuthProperty {
    private Authority authority;

    /**
     * 权限
     */
    @Data
    public static class Authority {
        private Set<String> roles;
        private Set<String> scopes;
        private Set<String> auths;
    }

    /**
     * 组装权限字符串
     * 目的：给 hasAnyAuthority() 方法生成参数
     * @return
     */
    public String getAllAuth() {
        StringBuilder res = new StringBuilder();

        // 角色
        Set<String> roles = this.authority.roles;
        // 角色非空时
        if (!CollectionUtils.isEmpty(roles)) {
            for (String role : roles) {
                res.append(role).append("','");
            }
            // 循环结果后，生成类似：x ',' y ',' z ','
        }

        // 范围
        Set<String> scopes = this.authority.scopes;
        // 非空时
        if (!CollectionUtils.isEmpty(scopes)) {
            for (String scope : scopes) {
                res.append("SCOPE_" + scope).append("','");
            }
            // 循环结果后，生成类似：x ',' y ',' z ',' SCOPE_a ',' SCOPE_b ',' SCOPE_c ','
        }

        // 细粒度权限
        Set<String> auths = this.authority.auths;
        // 非空时
        if (!CollectionUtils.isEmpty(auths)) {
            for (String auth : auths) {
                res.append(auth).append("','");
            }
            // 循环结果后，生成类似：x ',' y ',' z ',' SCOPE_a ',' SCOPE_b ',' SCOPE_c ',' l ',' m ',' n ','
        }

        // 如果res不为空，去掉最后多出的三个字符 ','
        int len = res.length();
        if (len > 3) {
            res.delete(len - 3, len);
        }

        return res.toString();
    }
}
