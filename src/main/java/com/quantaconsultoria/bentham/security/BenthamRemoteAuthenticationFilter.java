package com.quantaconsultoria.bentham.security;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationCredentialsNotFoundException;
import org.springframework.security.AuthenticationException;
import org.springframework.security.ui.AbstractProcessingFilter;

import us.monoid.json.JSONException;
import us.monoid.json.JSONObject;
import us.monoid.web.Resty;

public class BenthamRemoteAuthenticationFilter extends AbstractProcessingFilter {
	
	public static final String BENTHAM_REMOTE_TOKEN_KEY = "token";

	private String tokenParameter = BENTHAM_REMOTE_TOKEN_KEY;
	
	private String userDetailUrl;
	
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request) throws AuthenticationException {
		
		String token = obtainToken(request);
		
		if(token != null){
			
			try {
				Resty resty = new Resty();
				JSONObject jsonObject = resty.json(buildResourceUrl(request)).object();
				
				BethamRemoteAuthenticationToken authenticationToken = new BethamRemoteAuthenticationToken(jsonObject.get("login"), token);
				setDetails(request, authenticationToken);
				return this.getAuthenticationManager().authenticate(authenticationToken);
			} catch (JSONException e) {
				e.printStackTrace();
				throw new AuthenticationCredentialsNotFoundException("Invalid Token!");
			} catch (IOException e) {
				e.printStackTrace();
				throw new AuthenticationCredentialsNotFoundException("Invalid Token!");
			}
			
		} else {
			BethamRemoteAuthenticationToken tokenRequest = new BethamRemoteAuthenticationToken(null, token);
			
			return tokenRequest;
		}
	}
	
	@Override
	public String getDefaultFilterProcessesUrl() {
		return "/bentham_remote_token_check";
	}
	
	protected void setDetails(HttpServletRequest request, BethamRemoteAuthenticationToken authRequest) {
		authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
	}
	
	public int getOrder() {
		return 0;
	}

	private String obtainToken(HttpServletRequest request) {
		return request.getParameter(tokenParameter);
	}
	
	private String buildResourceUrl(HttpServletRequest request){
		StringBuilder sb = new StringBuilder();
		
		sb.append(getUserDetailUrl());
		sb.append("?token=").append(obtainToken(request));
		
		return sb.toString();
	}

	public String getUserDetailUrl() {
		return userDetailUrl;
	}

	public void setUserDetailUrl(String userDetailUrl) {
		this.userDetailUrl = userDetailUrl;
	}

}
