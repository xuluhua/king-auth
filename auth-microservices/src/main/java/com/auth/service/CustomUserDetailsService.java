package com.auth.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.auth.entity.User;
import com.auth.entity.CustomGrantedauthority;
import com.auth.entity.CustomUserDetails;
import com.auth.entity.Role;
import com.auth.feign.AuthFeignService;

@Service("userDetailsService")
public class CustomUserDetailsService implements UserDetailsService {

	@Autowired
	private AuthFeignService authFeignService;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		if(username == null || username.isEmpty()) {
			throw new UsernameNotFoundException(username);
		}
		User user = authFeignService.loadUserByUsername(username);
		List<Role> roles = authFeignService.loadRolesByUsername(username);
		List<CustomGrantedauthority> authorities = new ArrayList<CustomGrantedauthority>();
		for (Role role : roles) {
			authorities.add(new CustomGrantedauthority(role.getRolename()));
		}
		return new CustomUserDetails(user, authorities);
	}

}
