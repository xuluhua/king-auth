package com.auth.filter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import com.auth.utils.HttpStatus;
import com.fasterxml.jackson.databind.ObjectMapper;

@Component
public class CustomAccessDenieHandler implements AccessDeniedHandler {

	@Autowired
	private ObjectMapper objectMapper;
	
	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response,
			AccessDeniedException accessDeniedException) throws IOException, ServletException {
		Map<String, Object> map = new HashMap<String, Object>(2);
		map.put("code", HttpStatus.SC_FORBIDDEN);
		map.put("msg", "没有权限");
		response.setContentType("application/json;charset=UTF-8");
		response.getWriter().write(objectMapper.writeValueAsString(map));

	}

}
