package com.auth.feign;

import java.util.List;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import com.auth.entity.User;
import com.auth.entity.Role;

@FeignClient(name = "account-service", value = "account-service")
public interface AuthFeignService {

	@RequestMapping(value = "/user/{username}", method = RequestMethod.GET)
	User loadUserByUsername(@PathVariable("username") String username);
	
	@RequestMapping(value = "/role/{username}", method = RequestMethod.GET)
	List<Role> loadRolesByUsername(@PathVariable("username") String username);
	
	@RequestMapping(value = "/operations/{url}/{method}", method = RequestMethod.GET)
	List<Role> loadRolesByUrl(@PathVariable("url") String url, @PathVariable("method") String method);
}
