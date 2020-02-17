package com.springSecurityDemo.basicserver.config.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.springSecurityDemo.basicserver.config.exception.AjaxResponse;
import com.springSecurityDemo.basicserver.config.exception.CustomException;
import com.springSecurityDemo.basicserver.config.exception.CustomExceptionType;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
//SimpleUrlAuthenticationFailureHandler 登陆失败之后默认跳转到登陆页
@Component
public class MyAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {
    @Value("${spring.security.loginType}")
    private String loginType;
    private static ObjectMapper objectMapper = new ObjectMapper();
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception)
            throws IOException, ServletException {

        String errormessage = exception.getMessage();
        if ("Bad credentials".equals(exception.getMessage())){
            System.out.println(exception.getMessage());
            errormessage="密码错误";
        }else {

            errormessage=errormessage;
        }

        if(loginType.equalsIgnoreCase("JSON")){
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write(objectMapper.writeValueAsString(
                    AjaxResponse.error(new CustomException(
                            CustomExceptionType.USER_INPUT_ERROR,
                            errormessage))
            ));
        }else{
            //跳转到登陆页面
            super.onAuthenticationFailure(request,response,exception);
        }

    }
}
