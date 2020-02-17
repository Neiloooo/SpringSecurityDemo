package com.springSecurityDemo.basicserver.config.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.web.session.SessionInformationExpiredEvent;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

import javax.servlet.ServletException;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 *SessionInformationExpiredStrategy
 * 实现接口里面的onExpiredSessionDetected方法,当Session超时或非法的时候就会回调
 *
 */
public class MyExpiredSessionStrategy implements SessionInformationExpiredStrategy {
    private static ObjectMapper objectMapper = new ObjectMapper();
    //当Session超时或非法的时候就会回调
    @Override
    public void onExpiredSessionDetected(SessionInformationExpiredEvent event) throws IOException, ServletException {
        Map<String,Object> map  = new HashMap<>();
        map.put("code",0);
        map.put("msg","您已经在另外一台电脑或浏览器登录，被迫下线！");
        //event将自定义错误提示写回(或跳转页面类似)
        event.getResponse().setContentType("application/json;charset=UTF-8");
        event.getResponse().getWriter().write(
                objectMapper.writeValueAsString(map)
        );

    }
}