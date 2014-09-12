package com.quantaconsultoria.bentham.security;

import org.springframework.security.GrantedAuthority;
import org.springframework.security.providers.AbstractAuthenticationToken;

@SuppressWarnings("serial")
public class BethamRemoteAuthenticationToken extends AbstractAuthenticationToken {
	
	private final Object token;
    private final Object principal;

	public BethamRemoteAuthenticationToken(Object principal, Object token) {
		super(null);
		this.principal = principal;
		this.token = token;
		setAuthenticated(false);
	}
	
	public BethamRemoteAuthenticationToken(Object principal, Object token, GrantedAuthority[] authorities) {
		super(authorities);
		this.principal = principal;
		this.token = token;
		super.setAuthenticated(true);
	}

	public Object getCredentials() {
		return token;
	}

	public Object getPrincipal() {
		return principal;
	}
	
	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		if (isAuthenticated) {
			throw new IllegalArgumentException(
					"Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
		}

		super.setAuthenticated(false);
	}

}
