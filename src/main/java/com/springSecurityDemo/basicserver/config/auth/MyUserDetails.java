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
    /**************这几个参数一定要传递好,否则会导致无法登陆,原本是null,我们应该重写成我们定义的属性传递回去**/
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
