package com.auth.entity;

import org.springframework.security.core.GrantedAuthority;

public class CustomGrantedauthority implements GrantedAuthority {

	private String authority;
	
	public CustomGrantedauthority(String authority) {
		this.authority =authority;
	}
	
	public void setAuthority(String authority) {
		this.authority = authority;
	}
	
	@Override
	public String getAuthority() {
		return this.authority;
	}

}
