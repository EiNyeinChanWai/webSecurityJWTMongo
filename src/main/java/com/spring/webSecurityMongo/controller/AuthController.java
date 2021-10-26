package com.spring.webSecurityMongo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.spring.webSecurityMongo.config.CustomUserDetailsService;
import com.spring.webSecurityMongo.config.JwtUtilService;
import com.spring.webSecurityMongo.model.AuthRequest;
import com.spring.webSecurityMongo.model.AuthResponse;

@RestController
public class AuthController {
	@Autowired
	private AuthenticationManager authManager;
	
	@Autowired
	private CustomUserDetailsService userDetailsService;
	
	@Autowired
	private JwtUtilService jwtUtil;
	
	@RequestMapping (value="/auth", method=RequestMethod.POST)
	public ResponseEntity<?> createAuthToken(@RequestBody AuthRequest authRequest) throws Exception{
		try {
			authManager.authenticate(new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));
		}catch(DisabledException e) {
			throw new Exception("USER_DISABLED",e);
		}catch(BadCredentialsException e) {
			throw new Exception("INVALID_CREDENTIALS",e);
		}
		final UserDetails userDetails = userDetailsService.loadUserByUsername(authRequest.getUsername());
		final String token = jwtUtil.generateToken(userDetails);
		return ResponseEntity.ok(new AuthResponse(token));
	}
}
