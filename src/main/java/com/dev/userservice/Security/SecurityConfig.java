package com.dev.userservice.Security;

import com.dev.userservice.Filter.AuthenticationFilter;
import com.dev.userservice.Filter.AuthorizationFilter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity @RequiredArgsConstructor @Slf4j
public class SecurityConfig  {
    private final UserDetailsService userDetailsService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    private AuthenticationManager authenticationManager;
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        log.info("Security Filter Chain");

        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
        authenticationManager = authenticationManagerBuilder.build();

        AuthenticationFilter authenticationFilter = new AuthenticationFilter(authenticationManager); // Custom Authentication Filter
        authenticationFilter.setFilterProcessesUrl("/user/login");

        http.csrf().disable();
        http
            .addFilterBefore(new AuthorizationFilter(), UsernamePasswordAuthenticationFilter.class) // authorization filter
            .authorizeRequests()
                .antMatchers(HttpMethod.GET,"/user/login/**", "/token/refresh/**").permitAll()
                .antMatchers(HttpMethod.GET,"/users/**").hasAnyAuthority("ROLE_ADMIN")
                .antMatchers(HttpMethod.GET,"/user/save/**").hasAnyAuthority("ROLE_ADMIN")
                .antMatchers(HttpMethod.GET,"/role/save/**").hasAnyAuthority("ROLE_ADMIN")
                .antMatchers(HttpMethod.GET,"/role/addtouser/**").hasAnyAuthority("ROLE_ADMIN")
                .anyRequest().authenticated()
                .and()
                .authenticationManager(authenticationManager)
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(authenticationFilter); // authentication filter
        
        return http.build();
    }
}
