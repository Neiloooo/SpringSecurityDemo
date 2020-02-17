

# SpringSecurity

## 一、简介:

### **1.1SpringSecurity 的核心功能：**

- **Authentication**：认证，用户登陆的验证（解决你是谁的问题）
- **Authorization**：授权，授权系统资源的访问权限（解决你能干什么的问题）
- **安全防护**，**防止跨站请求**，**session 攻击**等

### 1.2与shiro的对比:

**Spring Security因为它的复杂，所以从功能的丰富性的角度更胜一筹：**

- Spring Security默认含有**对OAuth2.0的支持**，与**Spring Social一起使用完成社交媒体登录**也比较方便。shiro在这方面只能靠自己写代码实现。

  

## 二、HttpBaic模式与FormLogin模式登录认证

Spring Security的HttpBasic模式，比较简单，只是进行了通过携带Http的Header进行简单的登录验证，而且没有定制的登录页面，所以使用场景比较窄。

所以这里重点介绍FormLogin模式:

**formLogin模式的三要素：**

- 登录认证逻辑

- 资源访问控制规则，如：资源权限、角色权限

- 用户角色权限

### 2.0配置文件

```yml
server:
  port: 8888
  servlet:
    session:
      timeout: 10s #Session的超时时间,默认最小1分钟,小于1分钟也是1分钟
      cookie:
        http-only: true # 浏览器脚本无法访问cookie 安全
        secure: false #必须用https才能发送cookie

spring:
  jackson:
    date-format: yyyy-MM-dd HH:mm:ss
    time-zone: GMT+8
  datasource:
    driverClassName: com.mysql.cj.jdbc.Driver
    url: jdbc:mysql://localhost:3306/jpadata?useUnicode=true&characterEncoding=UTF8&useSSL=false&serverTimezone=GMT%2B8
    username: root
    password: root
  freemarker:
    cache: false # 缓存配置 开发阶段应该配置为false 因为经常会改
    suffix: .html # 模版后缀名 默认为ftl
    charset: UTF-8 # 文件编码
    template-loader-path: classpath:/templates/
  security:
    loginType: JSON
    user:
      name: admin
      password: admin


logging:
    config: classpath:log4j2-dev.xml

mybatis:
    configuration:
      mapUnderscoreToCamelCase: true
```

### 2.1SecurityConfig

```java
package com.springSecurityDemo.basicserver.config;

import com.springSecurityDemo.basicserver.config.auth.MyAuthenticationFailureHandler;
import com.springSecurityDemo.basicserver.config.auth.MyAuthenticationSuccessHandler;
import com.springSecurityDemo.basicserver.config.auth.MyExpiredSessionStrategy;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.annotation.Resource;

@Configuration
public class SecurityConfig  extends WebSecurityConfigurerAdapter {

    @Resource
    MyAuthenticationSuccessHandler mySuthenticationSuccessHandler;

    @Resource
    MyAuthenticationFailureHandler myAuthenticationFailureHandler;

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
        //关闭跨站请求保护
        http.csrf().disable()
             .formLogin()
                //登陆逻辑配置:
                //登陆页面,
                .loginPage("/login.html")
                .usernameParameter("uname") //登录表单form中用户名输入框input的name名，不修改的话默认是username
                .passwordParameter("pword") //form中密码输入框input的name名，不修改的话默认是password
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
                .antMatchers("/biz1","/biz2") //需要对外暴露的资源路径
                    .hasAnyAuthority("ROLE_user","ROLE_admin")  //user角色和admin角色都可以访问
                //.antMatchers("/syslog","/sysuser")
                    //.hasAnyRole("admin")  //admin角色可以访问
                    //.hasAnyAuthority("ROLE_admin")
                .antMatchers("/syslog").hasAuthority("sys:log") //通过权限id控制权限,有该权限id才能访问
                .antMatchers("/sysuser").hasAuthority("sys:user") //自定义key值,通过key值进行访问
                .anyRequest().authenticated()

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
        //静态配置用户
        auth.inMemoryAuthentication()
                .withUser("user")
                .password(passwordEncoder().encode("123456"))
                .roles("user")
                    .and()
                .withUser("admin")
                .password(passwordEncoder().encode("123456"))
                .authorities("sys:log","sys:user") //赋予资源id,放行其访问资源
                //.roles("admin")
                    .and()
                .passwordEncoder(passwordEncoder());//配置BCrypt加密
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(WebSecurity web) {
        //将项目中静态资源路径开放出来
        web.ignoring()
           .antMatchers( "/css/**", "/fonts/**", "/img/**", "/js/**");
    }

}
```

### 2.2自定义登陆成功拦截器

```java
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

```

### 2.2自定义登陆失败拦截器

```java
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
        if(loginType.equalsIgnoreCase("JSON")){
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write(objectMapper.writeValueAsString(
                    AjaxResponse.error(new CustomException(
                            CustomExceptionType.USER_INPUT_ERROR,
                            "用户名或者密码输入错误!"))
            ));
        }else{
            //跳转到登陆页面
            super.onAuthenticationFailure(request,response,exception);
        }

    }
}
```

### 2.3自定义Session超时回调类

```java
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
```

## 三、RBAC权限模型简介

### 3.1RBAC简介

RBAC权限模型（Role-Based Access Control）即：**基于角色的权限控制**。模型中有几个关键的术语：

- 用户：系统接口及访问的操作者
- 权限：能够访问某接口或者做某操作的授权资格
- 角色：具有一类相同操作权限的用户的总称

RBAC权限模型核心授权逻辑如下：

- 某用户是什么角色？
- 某角色具有什么权限？
- 通过角色的权限推导用户的权限

### 3.2 一个用户一个或多个角色

但是在实际的应用系统中，一个用户一个角色远远满足不了需求。如果我们希望一个用户既担任销售角色、又暂时担任副总角色。该怎么做呢？为了增加系统设计的适用性，我们通常设计：

- 一个用户有一个或多个角色
- 一个角色包含多个用户
- 一个角色有多种权限
- 一个权限属于多个角色

我们可以用下图中的数据库设计模型，描述这样的关系。
![img](https://img.kancloud.cn/39/fb/39fb0e5e70bdffa027f7c1f6f6c61788_999x329.png)

- sys_user是用户信息表，用于存储用户的基本信息，如：用户名、密码
- sys_role是角色信息表，用于存储系统内所有的角色
- sys_menu是系统的菜单信息表，用于存储系统内所有的菜单。用id与父id的字段关系维护一个菜单树形结构。
- sys_user_role是用户角色多对多关系表，一条userid与roleid的关系记录表示该用户具有该角色，该角色包含该用户。
- sys_role_menu是角色菜单(权限)关系表，一条roleid与menuid的关系记录表示该角色由某菜单权限，该菜单权限可以被某角色访问。

### 3.3.页面访问权限与操作权限

- **页面访问权限:** 所有系统都是由一个个的页面组成，页面再组成模块，用户是否能看到这个页面的菜单、是否能进入这个页面就称为页面访问权限。
- **操作权限：** 用户在操作系统中的任何动作、交互都需要有操作权限，如增删改查等。比如：某个按钮，某个超链接用户是否可以点击，是否应该看见的权限。

![img](https://img.kancloud.cn/f4/db/f4dbee8499923051601358026da5953b_999x340.png)

为了适应这种需求，我们可以把页面资源(菜单)和操作资源(按钮)分表存放，如上图。也可以把二者放到一个表里面存放，用一个字段进行标志区分。

## 四、结合实例解答RBAC权限模型

![img](https://img.kancloud.cn/40/4e/404e30860d655337dd09a1e279fea4cb_999x329.png)

- 用户与角色之间是多对多的关系，一个用户有多个角色，一个角色包含多个用户
- 角色与权限之间是多对多关系，一个角色有多种权限，一个权限可以属于多个角色

上图中：

- User是用户表，存储用户基本信息
- Role是角色表，存储角色相关信息
- Menu(菜单)是权限表，存储系统包含哪些菜单及其属性
- UserRole是用户和角色的关系表
- RoleMenu是角色和权限的关系表

> 本文讲解只将权限控制到菜单的访问级别，即控制页面的访问权限。如果想控制到页面中按钮级别的访问，可以参考Menu与RoleMenu的模式同样的实现方式。或者干脆在menu表里面加上一个字段区别该条记录是菜单项还是按钮。

为了有理有据，我们参考一个比较优秀的开源项目：若依后台管理系统。

### 4.1、组织部门管理

![img](https://img.kancloud.cn/bd/fd/bdfd5f432062fc304b4134159cd10c5a_792x312.png)

### 4.1.1需求分析

之所以先将部门管理提出来讲一下，是因为部门管理没有在我们上面的RBAC权限模型中进行提现。但是部门这样一个实体仍然是，后端管理系统的一个重要组成部分。通常有如下的需求：

- 部门要能体现出上下级的结构（如上图中的红框）。在关系型数据库中。这就需要使用到部门id及上级部门id，来组合成一个树形结构。这个知识是SQL学习中必备的知识，如果您还不知道，请自行学习。
- 如果组织与用户之间是一对多的关系，就在用户表中加上一个org_id标识用户所属的组织。原则是：实体关系在多的那一边维护。比如：是让老师记住自己的学生容易，还是让学生记住自己的老师更容易？
- 如果组织与用户是多对多关系，这种情况现实需求也有可能存在。比如：某人在某单位既是生产部长，又是技术部长。所以他及归属于技术部。也归属于生产部。对于这种情况有两种解决方案，把该人员放到公司级别，而不是放到部门级别。另外一种就是从数据库结构上创建User与Org组织之间的多对多关系。
- 组织信息包含一些基本信息，如组织名称、组织状态、展现排序、创建时间
- 另外，要有基本的组织的增删改查功能

### 4.1.2 组织部门表的CreateSQL

以下SQL以MySQL为例:

```sql
CREATE TABLE `sys_org` (
	`id` INT(11) NOT NULL AUTO_INCREMENT,
	`org_pid` INT(11) NOT NULL COMMENT '上级组织编码',
	`org_pids` VARCHAR(64) NOT NULL COMMENT '所有的父节点id',
	`is_leaf` TINYINT(4) NOT NULL COMMENT '0:不是叶子节点，1:是叶子节点',
	`org_name` VARCHAR(32) NOT NULL COMMENT '组织名',
	`address` VARCHAR(64) NULL DEFAULT NULL COMMENT '地址',
	`phone` VARCHAR(13) NULL DEFAULT NULL COMMENT '电话',
	`email` VARCHAR(32) NULL DEFAULT NULL COMMENT '邮件',
	`sort` TINYINT(4) NULL DEFAULT NULL COMMENT '排序',
	`level` TINYINT(4) NOT NULL COMMENT '组织层级',
	`status` TINYINT(4) NOT NULL COMMENT '0:启用,1:禁用',
	PRIMARY KEY (`id`)
)
COMMENT='系统组织结构表'
COLLATE='utf8_general_ci'
ENGINE=InnoDB;
```

注意：mysql没有oracle中的start with connect  by的树形数据汇总SQL。所以通常需要为了方便管理组织之间的上下级树形关系，需要加上一些特殊字段，如：org_pids：该组织所有上级组织id逗号分隔，即包括上级的上级；is_leaf是否是叶子结点；level组织所属的层级(1,2,3)。

### 4.4菜单权限管理

![img](https://img.kancloud.cn/bb/b7/bbb740e34e1c359befefe1e8a76230d6_1537x671.png)

### 4.4.1 需求分析

- 由上图可以看出，菜单仍然是树形结构，所以数据库表必须有id与menu_pid字段
- 必要字段：菜单跳转的url、是否启用、菜单排序、菜单的icon矢量图标等
- 最重要的是菜单要有一个权限标志，具有唯一性。通常可以使用菜单跳转的url路径作为权限标志。此标志作为权限管理框架识别用户是否具有某个页面查看权限的重要标志
- 需要具备菜单的增删改查基本功能
- 如果希望将菜单权限和按钮超链接相关权限放到同一个表里面，可以新增一个字段。用户标志该权限记录是菜单访问权限还是按钮访问权限。

### 4.4.2 菜单权限表的CreateSQL

```sql
CREATE TABLE `sys_menu` (
	`id` INT(11) NOT NULL AUTO_INCREMENT,
	`menu_pid` INT(11) NOT NULL COMMENT '父菜单ID',
	`menu_pids` VARCHAR(64) NOT NULL COMMENT '当前菜单所有父菜单',
	`is_leaf` TINYINT(4) NOT NULL COMMENT '0:不是叶子节点，1:是叶子节点',
	`menu_name` VARCHAR(16) NOT NULL COMMENT '菜单名称',
	`url` VARCHAR(64) NULL DEFAULT NULL COMMENT '跳转URL',
	`icon` VARCHAR(45) NULL DEFAULT NULL,
	`icon_color` VARCHAR(16) NULL DEFAULT NULL,
	`sort` TINYINT(4) NULL DEFAULT NULL COMMENT '排序',
	`level` TINYINT(4) NOT NULL COMMENT '菜单层级',
	`status` TINYINT(4) NOT NULL COMMENT '0:启用,1:禁用',
	PRIMARY KEY (`id`)
)
COMMENT='系统菜单表'
COLLATE='utf8_general_ci'
ENGINE=InnoDB;
```

### 4.7角色管理

![img](https://img.kancloud.cn/50/12/5012263fafb10688e6fbcca270978a38_795x754.png)
 上图为角色修改及分配权限的页面

### 4.7.1需求分析

- 角色本身的管理需要注意的点非常少，就是简单的增删改查。重点在于角色分配该如何做。
- 角色表包含角色id，角色名称，备注、排序顺序这些基本信息就足够了
- 为角色分配权限：以角色为基础勾选菜单权限或者操作权限，然后先删除sys_role_menu表内该角色的所有记录，在将新勾选的权限数据逐条插入sys_role_menu表。
- sys_role_menu的结构很简单，记录role_id与menu_id，一个角色拥有某一个权限就是一条记录。
- 角色要有一个全局唯一的标识，因为角色本身也是一种权限。可以通过判断角色来判断某用户的操作是否合法。
- 通常的需求：不会在角色管理界面为角色添加用户，而是在用户管理界面为用户分配角色。

### 4.7.2角色表与角色菜单权限关联表的的CreateSQL

```sql
CREATE TABLE `sys_role` (
	`id` INT(11) NOT NULL AUTO_INCREMENT,
	`role_name` VARCHAR(32) NOT NULL DEFAULT '0' COMMENT '角色名称(汉字)',
	`role_desc` VARCHAR(128) NOT NULL DEFAULT '0' COMMENT '角色描述',
	`role_code` VARCHAR(32) NOT NULL DEFAULT '0' COMMENT '角色的英文code.如：ADMIN',
	`sort` INT(11) NOT NULL DEFAULT '0' COMMENT '角色顺序',
	`status` INT(11) NULL DEFAULT NULL COMMENT '0表示可用',
	`create_time` DATETIME NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '角色的创建日期',
	PRIMARY KEY (`id`)
)
COMMENT='系统角色表'
COLLATE='utf8_general_ci'
ENGINE=InnoDB;
CREATE TABLE `sys_role_menu` (
	`id` INT(11) NOT NULL AUTO_INCREMENT,
	`role_id` INT(11) NOT NULL DEFAULT '0' COMMENT '角色id',
	`menu_id` INT(11) NOT NULL DEFAULT '0' COMMENT '权限id',
	PRIMARY KEY (`id`)
)
COMMENT='角色权限关系表'
COLLATE='utf8_general_ci'
ENGINE=InnoDB;
```

### 4.10.用户管理

![img](https://img.kancloud.cn/cd/32/cd32c2254e8856b12138adc6f5bc3f4c_1186x232.png)

### 4.10.1需求分析

- 上图中点击左侧的组织菜单树结点，要能显示出该组织下的所有人员（系统用户）。在组织与用户是一对多的关系中，需要在用户表加上org_id字段，用于查询某个组织下的所有用户。
- 用户表中要保存用户的用户名、加密后的密码。页面提供密码修改或重置的功能。
- 角色分配:实际上为用户分配角色，与为角色分配权限的设计原则是一样的。所以可以参考。
- 实现用户基本信息的增删改查功能

### 4.10.2.sys_user 用户信息表及用户角色关系表的CreateSQL

```sql
CREATE TABLE `sys_user` (
	`id` INT(11) NOT NULL AUTO_INCREMENT,
	`username` VARCHAR(64) NOT NULL DEFAULT '0' COMMENT '用户名',
	`password` VARCHAR(64) NOT NULL DEFAULT '0' COMMENT '密码',
	`create_time` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '创建时间',
	`org_id` INT(11) NOT NULL COMMENT '组织id',
	`enabled` INT(11) NULL DEFAULT NULL COMMENT '0无效用户，1是有效用户',
	`phone` VARCHAR(16) NULL DEFAULT NULL COMMENT '手机号',
	`email` VARCHAR(32) NULL DEFAULT NULL COMMENT 'email',
	PRIMARY KEY (`id`)
)
COMMENT='用户信息表'
COLLATE='utf8_general_ci'
ENGINE=InnoDB;
CREATE TABLE `sys_user_role` (
	`id` INT(11) NOT NULL AUTO_INCREMENT,
	`role_id` INT(11) NOT NULL DEFAULT '0' COMMENT '角色自增id',
	`user_id` INT(11) NOT NULL DEFAULT '0' COMMENT '用户自增id',
	PRIMARY KEY (`id`)
)
COMMENT='用户角色关系表'
COLLATE='utf8_general_ci'
ENGINE=InnoDB;
```

在用户的信息表中，体现了一些隐藏的需求。如：

多次登录锁定与锁定到期时间的关系。

账号有效期的设定规则等。

当然用户表中，根据业务的不同还可能加更多的信息，比如：用户头像等等。但是通常在比较大型的业务系统开发中，业务模块中使用的用户表和在权限管理模块使用的用户表通常不是一个，而是根据某些唯一字段弱关联，分开存放。这样做的好处在于：经常发生变化的业务需求，不会去影响不经常变化的权限模型。

## 五、加载动态数据进行登录与授权(重要)

实际的业务系统中,**用户与权限的对应关系**通常是存放在**RBAC权限模型的数据库表**中的

- RBAC的权限模型可以**从用户获取为用户分配的一个或多个角色**，从用户的角色又可以获取该角色的多种权限。通过**关联查询可以获取某个用户的角色信息和权限信息**。
- 如果我们不希望用户、角色、权限信息写死在配置里面。我们应该**实现UserDetails与UserDetailsService接口**，从而从**数据库或者其他的存储上动态的加载这些信息**。

### 5.1UserDetails与UserDetailsService接口

UserDetailsService接口有一个方法叫做**loadUserByUsername**，我们实现动态加载用户、角色、权限信息就是通过实现该方法。函数见名知义：通过用户名加载用户。该方法的**返回值就是UserDetails**(本质上是个实体类,Security会自动从里面取值进行对比)。

UserDetails就是用户信息，即：用户名、密码、该用户所具有的权限

源码中的**UserDetails接口**都有哪些方法:

```java
public interface UserDetails extends Serializable {
    //获取用户的权限集合
    Collection<? extends GrantedAuthority> getAuthorities();

    //获取密码
    String getPassword();

    //获取用户名
    String getUsername();

    //账号是否没过期
    boolean isAccountNonExpired();

    //账号是否没被锁定
    boolean isAccountNonLocked();

    //密码是否没过期
    boolean isCredentialsNonExpired();

    //账户是否可用
    boolean isEnabled();
}
```

**我们把这些信息提供给Spring Security**，Spring Security就知道怎么做登录验证了，

这也体现了Springboot的整体理念,**配置大于编码**,根本不**需要我们自己写Controller实现登录验证逻辑**。

### 5.2、实现UserDetails 接口

一个适应于**UserDetails的java POJO类**，所谓的 UserDetails接口**实现就是一些get方法**。get方法由Spring  Security调用，我们通过**set方法或构造函数为 Spring Security提供UserDetails数据**（从数据库查询）。

```java
package com.springSecurityDemo.basicserver.config.auth;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

/**
 * 实现用户信息接口,相当于Security又套了一层的用户实体类
 */
@NoArgsConstructor
@AllArgsConstructor
public class MyUserDetails implements UserDetails {

    //**********************************编写UserDetails相关属性
    public String password; //密码
    public String username;//用户名
    public boolean accountNonExpired; //当前账户是否过期
    public boolean accountNonLocked; //是否没被锁定
    public boolean credentialsNonExpired; //是否没过期
    public boolean enabled; // 账户是否可用
    Collection<? extends GrantedAuthority> authorities; // 用户权限集合

    //*****************通过下面的方法SpringSecuirty获取用户的的相关数据
    /**************这几个参数一定要传递好,否则会导致无法登陆,原本重写过来是null,我们应该重写成我们定义的属性传递回去**/
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        return this.authorities;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {

        return this.username;
    }


    //账号是否没过期
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    //是否没被锁定
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    //密码是否没过期
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    //账号是否可用
    @Override
    public boolean isEnabled() {
        return true;
    }

    //******************************自定义set方法对黑盒子进行赋值让springsecurity进行调用
    public void setPassword(String password)
    {
        this.password = password;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setAccountNonExpired(boolean accountNonExpired) {
        this.accountNonExpired = accountNonExpired;
    }

    public void setAccountNonLocked(boolean accountNonLocked) {
        this.accountNonLocked = accountNonLocked;
    }

    public void setCredentialsNonExpired(boolean credentialsNonExpired) {
        this.credentialsNonExpired = credentialsNonExpired;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public void setAuthorities(Collection<? extends GrantedAuthority> authorities) {
        this.authorities = authorities;
    }

}
```



### 5.3实现UserDetailsService接口

#### 5.3.0Dao层需要实现三个接口给Security查询出其想要的数据才能进行这部操作:

实现三个接口：一是**通过userId（用户名）查询用户信息**;二是**根据用户名查询用户角色列表**；三是**通过角色列表查询权限列表。**这里使用的是Mybatis

```java
public interface MyUserDetailsServiceMapper {

    //根据userID查询用户信息
    @Select("SELECT username,password,enabled\n" +
            "FROM sys_user u\n" +
            "WHERE u.username = #{userId}")
    MyUserDetails findByUserName(@Param("userId") String userId);

    //根据userID查询用户角色
    @Select("SELECT role_code\n" +
            "FROM sys_role r\n" +
            "LEFT JOIN sys_user_role ur ON r.id = ur.role_id\n" +
            "LEFT JOIN sys_user u ON u.id = ur.user_id\n" +
            "WHERE u.username = #{userId}")
    List<String> findRoleByUserName(@Param("userId") String userId);


    //根据用户角色查询用户权限
    @Select({
      "<script>",
         "SELECT url " ,
         "FROM sys_menu m " ,
         "LEFT JOIN sys_role_menu rm ON m.id = rm.menu_id " ,
         "LEFT JOIN sys_role r ON r.id = rm.role_id ",
         "WHERE r.role_code IN ",
         "<foreach collection='roleCodes' item='roleCode' open='(' separator=',' close=')'>",
            "#{roleCode}",
         "</foreach>",
      "</script>"
    })
    List<String> findAuthorityByRoleCodes(@Param("roleCodes") List<String> roleCodes);

}
```

- 通常数据库表**sys_user字段要和SysUser属性**一一对应，比如username、password、enabled。但是比如accountNonLocked字段用于登录多次错误锁定，但**我们一般不会在表里存是否锁定**，而是**存一个锁定时间字段**。通过锁定时间是否大于当前时间判断账号是否锁定，所以实现过程中可以灵活做判断并用好set方法，不必拘泥于一一对应的形式。
- 角色是一种特殊的权限，在Spring Security我们可以使用hasRole(角色标识)表达式判断用户是否具有某个角色，决定他是否可以做某个操作;**通过hasAuthority(权限标识)表达式判断是否具有某个操作权限。**

```java
package com.springSecurityDemo.basicserver.config.auth;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 实现UserDetailsService,来通过用户名获取用户信息(也是Security的起始验证)
 */
@Component
public class MyUserDetailsService implements UserDetailsService {

    //注入之前写的dao接口
    @Resource
    private MyUserDetailsServiceMapper myUserDetailsServiceMapper;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //1.加载基础用户信息 MyUserDetails是实现了UserDetails的实体类
        MyUserDetails myUserDetails = myUserDetailsServiceMapper.findByUserName(username);

        if(myUserDetails == null){
            throw new UsernameNotFoundException("用户名不存在");
        }

        //2.加载用户角色列表
        List<String> roleCodes = myUserDetailsServiceMapper.findRoleByUserName(username);
        //3.通过用户角色列表加载用户的资源权限列表
        List<String> authority = myUserDetailsServiceMapper.findAuthorityByRoleCodes(roleCodes);
        //3.1角色是一个特殊的权限,也要添加到查出来的权限列表中,Security中必须有ROLE_前缀(规定标识)
        roleCodes.stream()
                .map(rc->"ROLE_"+rc) //每个对象前加前缀
                .collect(Collectors.toList()); //再转换回List
        //4.添加修改好前缀的角色前缀的角色权限
        authority.addAll(roleCodes);

        //5.把权限类型的权限给UserDetails
        myUserDetails.setAuthorities(
                //逗号分隔的字符串转换成权限权限类型列表
                AuthorityUtils.commaSeparatedStringToAuthorityList(
                        //List转字符串,逗号分隔
                        String.join(",",authority)
                )
        );
        return myUserDetails; //全部交给springsecurity
    }
}
```

### 5.4注册UserDetailsService

重写WebSecurityConfigurerAdapter的 configure(AuthenticationManagerBuilder auth)方法

```java
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
```

使用BCryptPasswordEncoder，表示**存储中（数据库）取出的密码必须是经过BCrypt加密算法加密的。**

# 六、动态加载资源鉴权规则(重要)

简单说“**资源鉴权规则**”就是：你有哪些权限？这些权限能够访问哪些资源？即：权限与资源的匹配关系。

### 6.1SecurityConfiger中的配置:

```java
                //权限校验规则
             .authorizeRequests()
                //login页面和login的url谁都可以访问
                .antMatchers("/login.html","/login").permitAll()
//                        //权限表达式的使用:访问该url需要admin角色或ROLE_admin权限
//                .antMatchers("/system/*").access("hasAnyRole('admin') or hasAnyAuthority('ROLE_admin')")
                .antMatchers("/index").authenticated() //首页是只要登录了就可以访问
                //使用权限表达式规则 将自定义权限规则传入,所有url必须走我们写的权限规则方法,才能访问
                .anyRequest().access("@rbcaService.hasPermission(request,authentication)")
```

- 首先将静态规则去掉（注释掉的部分内容），这部分内容我们将替换为**动态从数据库加载**
- 登录页面“login.html”和登录认证处理路径“/login”需完全对外开发，不需任何鉴权就可以访问
- 首页**"/index"必须authenticated，即：登陆之后才能访问**。不做其他额外鉴权规则控制。
- 最后，其他的资源的访问我们通过**权限规则表达式**实现，表达式规则中使用了rbacService，这个类我们自定义实现。该**类服务hasPermission从内存(或数据库)动态加载资源匹配规则**，进行资源访问鉴权。

### 6.2动态资源鉴权规则

- 首先通过登录**用户名加载用户的urls（即资源访问路径、资源唯一标识**）。
- **如果urls列表中任何一个元素，能够和request.getRequestURI()请求资源路径相匹配，则表示该用户具有访问该资源的权限。**
- urls.stream().anyMatch是java8的语法，可以遍历数组，返回一个boolean类型。
- hasPermission有两个参数，第一个参数是HttpServletRequest ,第二个参数是Authentication认证主体
- **用户每一次访问系统资源的时候，都会执行这个方法，判断该用户是否具有访问该资源的权限。**

```java
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
			
            
            //2.从内存中获取权限(因为已经登录),放入security容器中,如果有的话返回true
    List<GrantedAuthority> authorityList =
          AuthorityUtils.commaSeparatedStringToAuthorityList(request.getRequestURI());
           
            return userDetails.getAuthorities().contains(authorityList.get(0));
            
            
            //2.通过用户名获取用户资源(用户找角色,角色找资源)(这里拿url做的标识,所以是url)
 //           List<String> urlByUserName = rbacServiceMapper.findUrlByUserName(username);

            //3.遍历urls,然后通过antPathMatcher判断是否匹配,匹配的上返回true
       //     return urlByUserName.stream().anyMatch(
      //              url -> antPathMatcher.match(url, request.getRequestURI())
       //     );

        }
        return false;
    }

}
```

**鉴权加载规则与方法级别的权限验证与参数验证略,可以自己找资料如果需要**