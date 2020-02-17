package com.springSecurityDemo.basicserver.config.auth;

import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import java.util.List;

public interface MyRBACServiceMapper {


    /**
     * 通过username查询该角色有的资源(url)
     * @param username
     * @return
     */
    @Select("SELECT url\n" +
            "FROM sys_menu m\n" +
            "    LEFT JOIN sys_role_menu rm ON m.id=rm.menu_id\n" +
            "    LEFT JOIN sys_role r ON r.id=rm.role_id\n" +
            "    LEFT JOIN sys_user_role sur on r.id = sur.role_id\n" +
            "    LEFT JOIN sys_user su on sur.user_id = su.id\n" +
            "where su.username=#{username} "
    )
    List<String> findUrlByUserName(@Param("username") String username);
}
