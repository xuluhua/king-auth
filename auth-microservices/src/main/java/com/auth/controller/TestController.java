package com.auth.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.auth.entity.User;
import com.auth.feign.AuthFeignService;

@RestController
public class TestController {

	@Autowired
	private AuthFeignService authFeignService;
	
	@ResponseBody
	@RequestMapping(value = "/user/{username}", method = RequestMethod.GET)
	public User getUser(@PathVariable("username") String username){
		return authFeignService.loadUserByUsername(username);
	}
	
}
