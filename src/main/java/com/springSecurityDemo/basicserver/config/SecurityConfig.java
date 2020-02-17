package com.springSecurityDemo.basicserver.config;

import com.springSecurityDemo.basicserver.config.auth.MyAuthenticationFailureHandler;
import com.springSecurityDemo.basicserver.config.auth.MyAuthenticationSuccessHandler;
import com.springSecurityDemo.basicserver.config.auth.MyExpiredSessionStrategy;
import com.springSecurityDemo.basicserver.config.auth.MyUserDetailsService;
import org.apache.tomcat.util.security.MD5Encoder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.MessageDigestPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import sun.security.provider.MD5;

import javax.annotation.Resource;
import javax.sql.DataSource;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true) //打开方法级别的安全控制
public class SecurityConfig  extends WebSecurityConfigurerAdapter {

    @Resource
    MyAuthenticationSuccessHandler mySuthenticationSuccessHandler;

    @Resource
    MyAuthenticationFailureHandler myAuthenticationFailureHandler;

    //将UserDetailsService的东西注入,通知security,我们Usertials东西配好了,给它
    @Resource
    MyUserDetailsService myUserDetailsService;

    @Resource
    private DataSource dataSource; //注入数据源,为记住我从数据控动态加载用户与令牌关系使用



    //重写Springsecuriry配置,以达到自定义的需求
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //httpBasic模式的设置 保护所有请求,作用不大,一般不用
        //因为很容易破解
//        http.httpBasic()
//                .and()
//                .authorizeRequests().anyRequest() //所有请求
//                .authenticated(); //必须登录后才能访问
//    }

        //formLogin模式
        //开启记住我模式
        //关闭跨站请求保护
        http.rememberMe()
                .rememberMeParameter("remrmber-me-new") //RembermeTOKEn传参的key值,需要前后端一致,让security来识别
                .rememberMeCookieName("asdasdada") // 浏览器中,可以考虑起个怪名字,rememberme中的cookie名称
                .tokenValiditySeconds(2*24*60*60) //记住我免登录的有效期,这里是两天
                .tokenRepository(persistentTokenRepository()) //记住密码的token存入数据库


                .and()
                .csrf().disable()
             .formLogin()
                //登陆逻辑配置:
                //登陆页面,
                .loginPage("/login.html")
                .usernameParameter("username") //登录表单form中用户名输入框input的name名，不修改的话默认是username
                .passwordParameter("password") //form中密码输入框input的name名，不修改的话默认是password
                //登录表单form中action的地址，也就是处理认证请求的路径
                .loginProcessingUrl("/login")  //拦截前端的登陆请求,交由SpringSecurity控制
                //.defaultSuccessUrl("/index") //登陆成功做页面跳转
                //.failureUrl("/login.html") //登陆失败页面
                .successHandler(mySuthenticationSuccessHandler) //自定义登陆成功处理结果与defaultSuccessUrl("/index")互相排斥
                .failureHandler(myAuthenticationFailureHandler) //自定义登陆失败逻辑
             .and()

                //权限校验规则
             .authorizeRequests()
                //login页面和login的url谁都可以访问
                .antMatchers("/login.html","/login").permitAll()
//                        //权限表达式的使用:访问该url需要admin角色或ROLE_admin权限
//                .antMatchers("/system/*").access("hasAnyRole('admin') or hasAnyAuthority('ROLE_admin')")
                .antMatchers("/index").authenticated() //首页是只要登录了就可以访问
                //使用权限表达式规则 将自定义权限规则传入,所有url必须走我们写的权限规则方法,才能访问
                .anyRequest().access("@rbcaService.hasPermission(request,authentication)")

                //写死的权限校验规则
//                .antMatchers("/biz1","/biz2") //需要对外暴露的资源路径
//                    .hasAnyAuthority("ROLE_user","ROLE_admin")  //user角色和admin角色都可以访问
//                //.antMatchers("/syslog","/sysuser")
//                    //.hasAnyRole("admin")  //admin角色可以访问
//                    //.hasAnyAuthority("ROLE_admin")
//                .antMatchers("/syslog").hasAuthority("/syslog") //通过权限id控制权限,有该权限id才能访问
//                .antMatchers("/sysuser").hasAuthority("/sysuser") //自定义key值,通过key值进行访问
//                .anyRequest().authenticated()



                //Session的管理
             .and().sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) //默认的也是需要的时候才会创建Session
                .invalidSessionUrl("/login.html") //Session超时登陆跳转的页面
                .sessionFixation().migrateSession() //每次Session复制一份,重新生成JSessionID,保障安全
                .maximumSessions(1) //最大当前只能有一个用户登陆
                .maxSessionsPreventsLogin(false) //允许再次登陆,之前登陆的会被踢掉
                .expiredSessionStrategy(new MyExpiredSessionStrategy()); //引入我们自定义的超过在线人数的回调函数

    }


    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
//        //静态配置用户
//        auth.inMemoryAuthentication()
//                .withUser("user")
//                .password(passwordEncoder().encode("123456"))
//                .roles("user")
//                    .and()
//                .withUser("admin")
//                .password(passwordEncoder().encode("123456"))
//                .authorities("sys:log","sys:user") //赋予资源id,放行其访问资源
//                //.roles("admin")
//                    .and()
//                .passwordEncoder(passwordEncoder());//配置BCrypt加密

        //从数据库中动态加载用户信息与权限
        //把做好的一系列myUserDetailsService信息交给security,并且设置加密方式
        auth.userDetailsService(myUserDetailsService)
                .passwordEncoder(passwordEncoder());

    }

    //重写加密器,设置加密
    @Bean("passwordEncoder")
    public PasswordEncoder passwordEncoder(){

        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(WebSecurity web) {
        //将项目中静态资源路径开放出来
        web.ignoring()
           .antMatchers( "/css/**", "/fonts/**", "/img/**", "/js/**");
    }


    /**
     *通过当前数据源获取token仓库的bean,给记住我功能用
     * @return
     */
    @Bean
    public PersistentTokenRepository persistentTokenRepository(){

        JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
        tokenRepository.setDataSource(dataSource);
        return tokenRepository;
    }

}
