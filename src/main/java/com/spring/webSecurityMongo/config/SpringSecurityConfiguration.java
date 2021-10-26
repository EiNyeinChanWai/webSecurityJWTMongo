package com.spring.webSecurityMongo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SpringSecurityConfiguration extends WebSecurityConfigurerAdapter{
	@Autowired
	CustomUserDetailsService userDetailsService;
	
	@Autowired
	private CustomAuthFilter customAuthFilter;
	
	@Autowired
	private CustomAuthEntryPoint unauthorizedHandler;
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
	}
	
	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}
	
	@Override
	public void configure(HttpSecurity httpSecurity) throws Exception {
		httpSecurity.csrf().disable()
			.authorizeRequests()
			.antMatchers(HttpMethod.DELETE).hasRole("MANAGEMENT")
			.antMatchers(HttpMethod.POST, "/api/v1").hasAnyRole("ADMIN", "MANAGEMENT")
			.antMatchers(HttpMethod.PUT).hasAnyRole("ADMIN", "MANAGEMENT")
			.antMatchers(HttpMethod.GET).hasAnyRole("USER", "ADMIN", "MANAGEMENT")
			.antMatchers("/auth").permitAll().anyRequest().authenticated()
			//if any exception occurs, call this
			.and().exceptionHandling().authenticationEntryPoint(unauthorizedHandler)
			//make sure we use stateless session, won't be store user's state
			.and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
			
			//remove httpbasic security, bcs we eill use jwt instead
			//.and().httpBasic();
		
		//add filter to validate the token with every request
		httpSecurity.addFilterBefore(customAuthFilter, UsernamePasswordAuthenticationFilter.class);
	}
}
