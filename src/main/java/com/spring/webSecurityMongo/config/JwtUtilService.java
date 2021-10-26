package com.spring.webSecurityMongo.config;

import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;

@Service
public class JwtUtilService {
	private String secret;
	private int jwtExpirationInMs;
	
	@Value("${jwt.secret}")
	public void setSecret(String secret) {
		this.secret = secret;
	}
	
	@Value("${jwt.jwtExpirationInMs}")
	public void setJwtExpirationInMs(int jwtExpirationInMs) {
		this.jwtExpirationInMs = jwtExpirationInMs;
	}
	
	//generate Token with respect to user type
	public String generateToken(UserDetails userDetails) {
		Map<String, Object> claims = new HashMap<>();
		Collection<? extends GrantedAuthority> roles = userDetails.getAuthorities();
		if(roles.contains(new SimpleGrantedAuthority("ROLE_MANAGEMENT"))) {
			claims.put("isManagement", true);
		}
		else if(roles.contains(new SimpleGrantedAuthority("ROLE_ADMIN"))) {
			claims.put("isAdmin", true);
		}
		else if(roles.contains(new SimpleGrantedAuthority("ROLE_USER"))) {
			claims.put("isUser", true);
		}
		String token = doGenerateToken(claims, userDetails.getUsername());
		System.out.println("token: "+token);
		return token;
	}
 
	private String doGenerateToken(Map<String, Object> claims, String username) {
		return Jwts.builder()
				.setClaims(claims)
				.setSubject(username)
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis()+jwtExpirationInMs))
				.signWith(SignatureAlgorithm.HS512,secret)
				.compact();
	}
	
	//validate token
	public boolean validateToken(String authToken) {
		try {//Jwt token has not been tempered with
			Jws<Claims> claim = Jwts.parser().setSigningKey(secret).parseClaimsJws(authToken);
			return true;
		}catch (SignatureException | MalformedJwtException | UnsupportedJwtException | IllegalArgumentException ex) {
			throw new BadCredentialsException("INVALID_CREDENTIALS", ex);
		}catch (ExpiredJwtException ex) {
			throw ex;
		}
	}
	
	public String getUsernameFromToken(String token) {
		Claims claim = Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
		return claim.getSubject();		
	}
	
	public List<SimpleGrantedAuthority> getRolesFromToken(String token){
		List<SimpleGrantedAuthority> roles = null;
		Claims claim = Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
		Boolean isManagement = claim.get("isManagement", Boolean.class);
		Boolean isAdmin = claim.get("isAdmin", Boolean.class);
		Boolean isUser = claim.get("isUser", Boolean.class);
		if(isManagement != null && isManagement == true) {
			roles = Arrays.asList(new SimpleGrantedAuthority("ROLE_MANAGEMENT"));
		}
		if(isAdmin != null && isAdmin == true) {
			roles = Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN"));
		}
		if(isUser != null && isUser == true) {
			roles = Arrays.asList(new SimpleGrantedAuthority("ROLE_USER"));
		}
		return roles;
	}
}
