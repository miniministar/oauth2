package com.example.oauth2resource01.util;

import lombok.AccessLevel;
import lombok.Data;
import lombok.Setter;

import java.time.LocalDateTime;

/**
 * <p>结果对象</p>
 *
 * //@Setter(AccessLevel.NONE) 表示禁用set方法，防止篡改结果
 */
@Data
@Setter(AccessLevel.NONE)
public class Result {
    /**
     * 返回码
     */
    private Integer code;
    /**
     * 数据
     */
    private Object data;
    /**
     * 时间
     */
    private LocalDateTime time;

    public Result(Integer code,Object data){
        this.code = code;
        this.data = data;
        this.time = LocalDateTime.now();
    }
}
