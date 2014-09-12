package com.quantaconsultoria.bentham.security;


import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.providers.AuthenticationProvider;
import org.springframework.util.Assert;

public class BenthamRemoteAuthenticationProvider implements AuthenticationProvider{
	
	public Authentication authenticate(Authentication authentication)
			throws AuthenticationException {
		Assert.isInstanceOf(BethamRemoteAuthenticationToken.class, authentication,
				"Only BethamRemoteAuthenticationToken is supported");
		
		BethamRemoteAuthenticationToken bethamRemoteAuthentication = (BethamRemoteAuthenticationToken) authentication;
		
		GrantedAuthority[] grantedAuthorities = {new GrantedAuthorityImpl("ROLE_USER")};
		
		Object principal = bethamRemoteAuthentication.getPrincipal();
		Object token = bethamRemoteAuthentication.getCredentials();
		
		if(principal != null && token != null){
			return new BethamRemoteAuthenticationToken(principal, token, grantedAuthorities);
		}
		
		return null;
	}
	
	@SuppressWarnings("rawtypes")
	public boolean supports(Class authentication) {
		return (BethamRemoteAuthenticationToken.class.isAssignableFrom(authentication));
	}
	
}
