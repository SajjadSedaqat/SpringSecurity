package com.sajjad.springsecurity.security;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;


@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig {


    //This How to use Basic Auth
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests()
                //This is a replacement for antMatcher
                .requestMatchers("/*", "index", "/css/*" , "/js/*").permitAll()
                //This says any other request
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();


        return http.build();
    }



}
