package com.springboot.cognito.security;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.web.servlet.HandlerExceptionResolver;

@SuppressWarnings("deprecation")
@Configuration
@EnableWebSecurity
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
	@Qualifier("handlerExceptionResolver")
	private HandlerExceptionResolver exceptionResolver;

	
	 @Override
	    protected void configure(HttpSecurity http) throws Exception {

	        http.cors().and().csrf().disable()
	                .authorizeRequests(expressionInterceptUrlRegistry -> expressionInterceptUrlRegistry
	                .antMatchers("/user/**").permitAll()
	                .anyRequest()
	                .authenticated())
	                .oauth2ResourceServer()
	                .jwt();
	    }
}