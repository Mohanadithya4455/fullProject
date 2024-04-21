package com.example.demo.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService getDetailsService() {
        return new CustomUserDetailsService();
    }

    @Bean
    public DaoAuthenticationProvider getAuthenticationProvider() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(getDetailsService());
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        return daoAuthenticationProvider;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

       /* String[] staticResources  =  {
                "/css/**",
                "src/main/resources/static/image/**",
                "/fonts/**",
                "/scripts/**",
        };*/
        http.csrf().disable()
                .authorizeHttpRequests()
                .requestMatchers("/register", "/login", "/createUser","/profile").permitAll()

                .requestMatchers("/display").authenticated()
                .requestMatchers("/images/maxresdefault.jpg").authenticated()
                .requestMatchers("/sales").authenticated()
                .requestMatchers("/data").authenticated()
                .requestMatchers("/successful").authenticated()
               .requestMatchers("/status/{id}").authenticated()
                .and()
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/userLogin")
                .defaultSuccessUrl("/display") // Redirect to "/display" after successful login
                .permitAll();
        return http.build();
    }

}

