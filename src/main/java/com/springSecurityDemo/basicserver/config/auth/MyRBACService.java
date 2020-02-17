package com.springSecurityDemo.basicserver.config.auth;


import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.util.List;

@Component("rbcaService") //给这个bean取名
public class MyRBACService {


    @Resource
    private MyRBACServiceMapper rbacServiceMapper;

    //security提供的工具类
    private AntPathMatcher antPathMatcher = new AntPathMatcher();

    /**
     * 判断某用户是否有该请求资源的访问权限
     *
     * @param request
     * @param authentication
     * @return
     */
    public boolean hasPermission(HttpServletRequest request,
                                 Authentication authentication) {
        //从security中拿出用户主体,实际上是我们之前封装的UserDetials,
        //但是又被封了一层
        Object principal = authentication.getPrincipal();


        //如果取出的principal是我们放进去的UserDetails类,并且已经登录
        if (principal instanceof UserDetails) {
            //1.强转获取name
            String username = ((UserDetails) principal).getUsername();

            //2.通过用户名获取用户资源(用户找角色,角色找资源)(这里拿url做的标识,所以是url)
            List<String> urlByUserName = rbacServiceMapper.findUrlByUserName(username);

            //3.遍历urls,然后通过antPathMatcher判断是否匹配,匹配的上返回true
            return urlByUserName.stream().anyMatch(
                    url -> antPathMatcher.match(url, request.getRequestURI())
            );
        }
        return false;
    }

}
