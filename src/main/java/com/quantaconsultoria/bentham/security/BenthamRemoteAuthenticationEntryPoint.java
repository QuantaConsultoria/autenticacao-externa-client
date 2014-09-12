package com.quantaconsultoria.bentham.security;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.AuthenticationException;
import org.springframework.security.ui.AuthenticationEntryPoint;
import org.springframework.security.util.RedirectUrlBuilder;
import org.springframework.security.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

public class BenthamRemoteAuthenticationEntryPoint implements AuthenticationEntryPoint, InitializingBean {
	
	private String authenticationUrl;
	private String clientId;
	
	public BenthamRemoteAuthenticationEntryPoint(String authenticationUrl, String clientId) {
		this.authenticationUrl = authenticationUrl;
		this.clientId = clientId;
	}
	
	public void afterPropertiesSet() throws Exception {
		Assert.isTrue(StringUtils.hasText(authenticationUrl) && UrlUtils.isValidRedirectUrl(authenticationUrl),
				"authenticationUrl must be specified and must be a valid redirect URL");
		Assert.hasText(clientId, "clientId must be specified");
	}
	
	public void commence(ServletRequest request, ServletResponse response, AuthenticationException authException) throws IOException, ServletException {
		HttpServletRequest httpRequest = (HttpServletRequest) request;
		HttpServletResponse httpResponse = (HttpServletResponse) response;
		
		String redirectUrl = buildRedirectUrl(httpRequest);
		httpResponse.sendRedirect(httpResponse.encodeRedirectURL(redirectUrl));
	}
	
	private String buildBaseUrl(HttpServletRequest request){
		RedirectUrlBuilder urlBuilder = new RedirectUrlBuilder();
		
		urlBuilder.setScheme(request.getScheme());
		urlBuilder.setServerName(request.getServerName());
		urlBuilder.setPort(request.getServerPort());
		urlBuilder.setContextPath(request.getContextPath());
		urlBuilder.setPathInfo("/bentham_remote_token_check");
		
		return urlBuilder.getUrl();
	}
	
	private String buildRedirectUrl(HttpServletRequest request){
		StringBuilder sb = new StringBuilder();
		
		sb.append(authenticationUrl);
		sb.append("?appId=").append(clientId);
		sb.append("&url=").append(buildBaseUrl(request));
		
		return sb.toString();
	}

}
