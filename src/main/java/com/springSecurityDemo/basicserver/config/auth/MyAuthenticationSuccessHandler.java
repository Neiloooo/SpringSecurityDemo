package com.springSecurityDemo.basicserver.config.auth;

        import com.fasterxml.jackson.databind.ObjectMapper;
        import com.springSecurityDemo.basicserver.config.exception.AjaxResponse;
        import org.springframework.beans.factory.annotation.Value;
        import org.springframework.security.core.Authentication;
        import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
        import org.springframework.stereotype.Component;

        import javax.servlet.ServletException;
        import javax.servlet.http.HttpServletRequest;
        import javax.servlet.http.HttpServletResponse;
        import java.io.IOException;

/**
 * 登陆成功结果处理
 */

//通常我们不会直接继承AuthenticationSuccessHandler
//继承SavedRequestAwareAuthenticationSuccessHandler 能 跳转到登陆之前未登陆请求的页面
@Component
public class MyAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {
    @Value("${spring.security.loginType}") //通过@value加载配置文件中的参数
    private String loginType;
    //JACKjson的 对象与json字符串转换类
    private static ObjectMapper objectMapper = new ObjectMapper();
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws ServletException, IOException {
        if(loginType.equalsIgnoreCase("JSON")){ //如果配置文件里是JSON,那么就用JSON方式做响应
            //JSon的数据格式进行数据相应
            response.setContentType("application/json;charset=UTF-8");
            //objectMapper.writeValueAsString 对象转换成字符串
            response.getWriter().write(objectMapper.writeValueAsString(
                    AjaxResponse.success("/index")
            ));
        }else{
            //跳转到登陆之前请求的页面(记录上一次登陆后的请求,如果登陆成功还会跳转到上一次跳转到的页面)
            super.onAuthenticationSuccess(request,response,authentication);
        }
    }
}
