package com.auth.authenorize;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.stereotype.Component;

import com.auth.entity.Role;
import com.auth.feign.AuthFeignService;

@Component
public class CustomSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {

	@Autowired
	private AuthFeignService authFeignService;

	/*
	 * @param 被调用的保护资源
	 * 
	 * @return 返回能够访问该保护资源的角色集合，如果没有，则应返回空集合。
	 */
	@Override
	public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
		FilterInvocation filterInvocation = (FilterInvocation) object;

		String url = filterInvocation.getRequestUrl();
		String requestMethod = filterInvocation.getHttpRequest().getMethod();

		List<Role> roles = this.authFeignService.loadRolesByUrl(url, requestMethod);
		if (roles == null || roles.size() == 0) {
			return null;
		}
		Collection<ConfigAttribute> rs = new ArrayList<ConfigAttribute>();
		for (Role role : roles) {
			rs.add(new SecurityConfig(role.getRolename()));
		}
		return rs;
	}

	@Override
	public Collection<ConfigAttribute> getAllConfigAttributes() {
		return null;
	}

	@Override
	public boolean supports(Class<?> clazz) {
		return FilterInvocation.class.isAssignableFrom(clazz);
	}

}
