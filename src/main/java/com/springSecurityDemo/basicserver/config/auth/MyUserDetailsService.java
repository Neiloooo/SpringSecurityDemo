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
