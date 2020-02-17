package com.springSecurityDemo.basicserver.config.auth;

import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import javax.annotation.Resource;
import java.util.List;

/**
 * 与数据库通信的用户信息接口
 * 对于UserDetails信息的查询与返回
 */

public interface MyUserDetailsServiceMapper {

    //1.根据userID查询用户信息,这里相当于调用了set方法为MyUserDetails类赋值
    @Select("SELECT username,password,enabled\n" +
            "FROM sys_user u\n" +
            "Where u.username = #{userId} ")
    MyUserDetails findByUserName(@Param("userId") String userId);



    //根据userID查询用户角色列表
   @Select("SELECT role_code\n"+
           "FROM sys_role r\n"+
           "LEFT JOIN sys_user_role ur ON r.id=ur.role_id\n"+
           "LEFT JOIN sys_user u ON  u.id=ur.user_id\n"+
           "WHERE u.username =#{userId} "
   )
   List<String> findRoleByUserName(@Param("userId") String userID);


    //根据用户角色(列表,需要先遍历然后在根据roleCode)查询用户权限唯一表示(这里是url)
    @Select({
                    "<script>",
                            "SELECT url",
                            "FROM sys_menu m",
                            "LEFT JOIN sys_role_menu rm ON  m.id=rm.menu_id" ,
                            "LEFT JOIN sys_role r ON  r.id=rm.role_id" ,
                            "WHERE r.role_code IN " ,
                                    "<foreach collection='roleCodes' item='roleCode' open='(' separator=',' close =')'>",
                                    "#{roleCode}",
                                    "</foreach>",
                    "</script>"
            })
    List<String> findAuthorityByRoleCodes(@Param("roleCodes") List<String> roleCodes);
}
