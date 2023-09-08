package com.example.oauth2server9000.entity;

import cn.hutool.core.collection.CollectionUtil;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;

import javax.persistence.*;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

@Data
@Entity
@Table(name = "sys_user")
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User {
    @Column(name = "id")
    @Id
    private Integer id;

    @Column(name = "username")
    private String username;

    @Column(name = "password")
    private String password;

    @Column(name = "nickname")
    private String nickname;

    @Column(name = "gender")
    private Integer gender;

    @Column(name = "dept_id")
    private Integer deptId;

    @Column(name = "status")
    private Integer status;

    // 数据权限(0-所有数据；1-部门及子部门数据；2-本部门数据；3-本人数据)
    @Transient
    private Integer dataScope;


    @Transient
    private List<String> roles;

    public UserDetails getDetail() {
        org.springframework.security.core.userdetails.User.UserBuilder builder = org.springframework.security.core.userdetails.User.builder();
        builder.username(this.username)
                .password(this.password);
        if(CollectionUtil.isNotEmpty(this.roles)) {
            String[] roles = (String[]) this.roles.toArray();
            builder.roles(roles);
            builder.authorities(roles);
        }else {
            builder.roles("USER");
            builder.authorities("USER");
        }
        UserDetails user = builder.build();
        return user;
    }
}
