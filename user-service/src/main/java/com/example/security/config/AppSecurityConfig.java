package com.example.security.config;

import com.example.common.UserPermission;
import com.example.security.JWT.AuthEntryPointJwt;
import com.example.security.fillter.AuthTokenFilter;
import com.example.security.service.AppUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class AppSecurityConfig  {
    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }
    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;
    @Autowired
    AppUserDetailService userDetailsService;
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authentication) throws Exception {
        return authentication.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .cors()
                .and()
                .csrf().disable()
                .httpBasic()
                .disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                .exceptionHandling().authenticationEntryPoint(unauthorizedHandler);
        ;
        ;
        http
                .authorizeRequests()
                .antMatchers(HttpMethod.GET,"/api/user/**").hasAnyAuthority(UserPermission.USER_READ.getPermission())
                .antMatchers("/api/admin/**").hasAnyAuthority(UserPermission.ADMIN_READ.getPermission(),UserPermission.ADMIN_WRITE.getPermission())
                .antMatchers("/api/auth/**").permitAll()
                .antMatchers("/**").permitAll()
        ;
        http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
        return http.build();

    }

}
