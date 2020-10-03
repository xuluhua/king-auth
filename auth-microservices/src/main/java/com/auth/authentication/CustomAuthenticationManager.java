package com.auth.authentication;

import java.nio.file.ProviderNotFoundException;
import java.util.Objects;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class CustomAuthenticationManager implements AuthenticationManager {

	private CustomAuthenticationProvider customAuthenticationProvider;

	public CustomAuthenticationManager(CustomAuthenticationProvider customAuthenticationProvider) {
		this.customAuthenticationProvider = customAuthenticationProvider;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		Authentication result = customAuthenticationProvider.authenticate(authentication);
		if (Objects.nonNull(result)) {
			return result;
		}
		throw new ProviderNotFoundException("Authentication failed");
	}

}
