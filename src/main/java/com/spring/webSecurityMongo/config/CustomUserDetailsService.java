package com.spring.webSecurityMongo.config;

import java.util.Arrays;
import java.util.List;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService{

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		List<SimpleGrantedAuthority> roles = null;
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		/* 
		 * User Password: $2a$10$/v0d3uBCWx3l6kTL5SA3MetsYAWiiuPVwYgG0MItut3oFqLc/YpEy
		   Admin Password: $2a$10$uNuyU0hJA6qNQyVKY2ClyufU3V.ptSgkrDEtrKN7sxmEDPfQbP.JK
		   Management Password: $2a$10$urbvx1osLLhFgpBQu/xsquYEgE2ftMJKVNLnmXtVmP6.DtwhsrD3y
		 */
		if(username.equals("management")) {
			roles = Arrays.asList(new SimpleGrantedAuthority("ROLE_MANAGEMENT"));
			String managementPassword = encoder.encode("managementPassword");
			System.out.println("Management Password: "+managementPassword);
			return new User("management", managementPassword, roles);
		}else if(username.equals("admin")) {
			roles = Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN"));
			String adminPassword = encoder.encode("adminPassword");
			System.out.println("Admin Password: "+adminPassword);
			return new User("admin", adminPassword, roles);
		}
		else if(username.equals("user")) {
			roles = Arrays.asList(new SimpleGrantedAuthority("ROLE_USER"));
			String userPassword = encoder.encode("userPassword");
			System.out.println("User Password: "+userPassword);
			return new User("user", userPassword, roles);
		}
		throw new UsernameNotFoundException("User not found with username: "+username);
	}
	
}
