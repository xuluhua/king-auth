package com.auth.authenorize;

import java.util.Collection;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.intercept.RunAsManager;
import org.springframework.security.core.Authentication;

public class CustomNullRunAsManager implements RunAsManager {

	@Override
	public Authentication buildRunAs(Authentication authentication, Object object,
			Collection<ConfigAttribute> attributes) {
		return null;
	}

	@Override
	public boolean supports(ConfigAttribute attribute) {
		return false;
	}

	@Override
	public boolean supports(Class<?> clazz) {
		return true;
	}

}
