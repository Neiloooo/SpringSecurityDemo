package com.springSecurityDemo.basicserver;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@MapperScan(basePackages = {"com.springSecurityDemo.basicserver.config.auth"})
public class BasicServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(
                BasicServerApplication.class, args);
    }

}
