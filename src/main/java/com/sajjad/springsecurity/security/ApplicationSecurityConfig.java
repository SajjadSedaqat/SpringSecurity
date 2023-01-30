package com.sajjad.springsecurity.security;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static com.sajjad.springsecurity.security.ApplicationUserRole.ADMIN;
import static com.sajjad.springsecurity.security.ApplicationUserRole.STUDENT;


@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig {

    private final PasswordEncoder passwordEncoder;

    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }


    //This How to use Basic Auth
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests()
                //This is a replacement for antMatcher
                .requestMatchers("/*", "index", "/css/*", "/js/*").permitAll()
                //Important This is for role base authentication we are just using roles not Permissions Important
                .requestMatchers("/api/**").hasRole(STUDENT.name())
                //This says any other request
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();


        return http.build();
    }


    @Bean
    public InMemoryUserDetailsManager userDetailsService() {

        UserDetails userDetails = User.builder()
                .username("Sajjad")
                .password(passwordEncoder.encode("123456"))
                //Important This is for role base authentication we are just using roles not Permissions Important
                .roles(STUDENT.name()) // This internally be ROLE_STUDENT
                .build();

        UserDetails adminDetails = User.builder()
                .username("admin")
                .password(passwordEncoder.encode("123456"))
                //We can have more than one role for a user
                //Important This is for role base authentication we are just using roles not Permissions Important
                .roles(ADMIN.name()) // ROLE_ADMIN
                .build();


        return new InMemoryUserDetailsManager(userDetails, adminDetails);
    }


}
