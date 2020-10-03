package com.auth.authenorize;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.SecurityMetadataSource;
import org.springframework.security.access.intercept.InterceptorStatusToken;
import org.springframework.security.web.FilterInvocation;
import org.springframework.stereotype.Component;

@Component
public class CustomFilterSecurityInterceptor extends CustomSecurityInterceptor implements Filter {

	private static final String FILTER_APPLIED = "__spring_security_filterSecurityInterceptor_filterApplied";

	@Autowired
	private CustomSecurityMetadataSource securityMetadataSource;

	private boolean observeOncePerRequest = false;

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		// TODO Auto-generated method stub
		Filter.super.init(filterConfig);
	}

	@Override
	public void destroy() {
		// TODO Auto-generated method stub
		Filter.super.destroy();
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		FilterInvocation filterInvocation = new FilterInvocation(request, response, chain);
		invoke(filterInvocation);

	}
	
	public void invoke(FilterInvocation filterInvocation) throws IOException,ServletException {
		if ((filterInvocation.getRequest() != null) && (filterInvocation.getRequest().getAttribute(FILTER_APPLIED) != null)
				 && observeOncePerRequest) {
			filterInvocation.getChain().doFilter(filterInvocation.getRequest(), filterInvocation.getResponse());
		}
		else {
			if (filterInvocation.getRequest() != null && observeOncePerRequest) {
				filterInvocation.getRequest().setAttribute(FILTER_APPLIED, Boolean.TRUE);
			}
			
			InterceptorStatusToken token = super.beforeInvocation(filterInvocation);
			
			try {
				filterInvocation.getChain().doFilter(filterInvocation.getRequest(), filterInvocation.getResponse());
			} catch (Exception e) {
				
			}
			finally {
				super.finallyInvocation(token);
			}
			super.afterInvocation(token, null);
		}
	}

	public CustomSecurityMetadataSource getSecurityMetadataSource() {
		return securityMetadataSource;
	}

	public void setSecurityMetadataSource(CustomSecurityMetadataSource securityMetadataSource) {
		this.securityMetadataSource = securityMetadataSource;
	}
	
	public boolean isObserveOncePerRequest() {
		return observeOncePerRequest;
	}

	public void setObserveOncePerRequest(boolean observeOncePerRequest) {
		this.observeOncePerRequest = observeOncePerRequest;
	}

	@Override
	public Class<?> getSecureObjectClass() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public SecurityMetadataSource obtainSecurityMetadataSource() {
		return this.securityMetadataSource;
	}

}
