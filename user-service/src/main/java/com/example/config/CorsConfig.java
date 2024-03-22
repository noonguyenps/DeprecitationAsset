package com.example.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CorsConfig {
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                        .allowedMethods("GET","POST","DELETE","PUT")
                        .allowedOriginPatterns("*")
                        .allowedHeaders("*")
                        .allowedOrigins("http://localhost:3000/","http://localhost:8080/"
                        ,"http://localhost:3001/","http://localhost:3002/")
                        .allowCredentials(true)
                        .maxAge(36000);
            }
        };
    }
}
