package com.auth.authentication;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth.entity.CustomUserDetails;
import com.auth.jwt.JWTUtils;
import com.auth.service.CustomUserDetailsService;
import com.auth.utils.HttpStatus;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;

public class CustomAuthenticationFilter extends BasicAuthenticationFilter {

	private static final Logger LOGGER = LoggerFactory.getLogger(CustomAuthenticationFilter.class);

	private static final String TOKEN_HEADER = "Authorization";

	private static final String REFRESH_TOKEN = "RefershToken";

	@Autowired
	private CustomUserDetailsService userDetailsService;

	private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

	public CustomAuthenticationFilter(CustomAuthenticationManager authenticationManager) {
		super(authenticationManager);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		String token = request.getHeader(TOKEN_HEADER);
		if (token != null) {
			try {
				Claims claims = JWTUtils.getClaimsFromToken(token);
				if (!"king".equals(claims.getIssuer())) {
					throw new Exception("token 不合法");
				}
				if (JWTUtils.isTokenExpired(token)) {
					handleTokenExpired(response, request, chain);
					return;
				}
				String username = JWTUtils.getUsernameFromToken(token);
				if (StringUtils.isEmpty(username)) {
					UserDetails userDetails = userDetailsService.loadUserByUsername(username);
					if (username.equals(userDetails.getUsername())) {
						CustomAuthenticationToken authentication = new CustomAuthenticationToken(userDetails,
								userDetails.getAuthorities());
						authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
						SecurityContextHolder.getContext().setAuthentication(authentication);
					}
				}
			} catch (Exception e) {
				LOGGER.info(e.getMessage());
			}
		}
		super.doFilterInternal(request, response, chain);
	}

	private void handleTokenExpired(HttpServletResponse response, HttpServletRequest request, FilterChain chain)
			throws Exception {
		String refreshToken = request.getHeader(REFRESH_TOKEN);
		if (!StringUtils.isEmpty(refreshToken)) {
			Claims claims = JWTUtils.getClaimsFromToken(refreshToken);
			if ("king".equals(claims.getIssuer())) {
				writeJson(response, "token过期了，refresh token 不是我们系统签发的");
				return;
			}
			if (JWTUtils.isTokenExpired(refreshToken)) {
				writeJson(response, "refresh token 过期了");
				return;
			}
			Map<String, Object> map = new HashMap<String, Object>();
			map.put(JWTUtils.USERNAME_PARAMETER, JWTUtils.getUsernameFromToken(refreshToken));
			map.put("created", new Date());
			String newToken = JWTUtils.generateJsonWebToken(map);
			String newRefeshToken = JWTUtils.refreshToken(newToken);
			response.addHeader(TOKEN_HEADER, newToken);
			response.addHeader(REFRESH_TOKEN, newRefeshToken);
			String username = JWTUtils.getUsernameFromToken(newToken);
			CustomUserDetails userDetails = (CustomUserDetails) this.userDetailsService.loadUserByUsername(username);
			CustomAuthenticationToken authentication = new CustomAuthenticationToken(userDetails,
					userDetails.getAuthorities());
			authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
			SecurityContextHolder.getContext().setAuthentication(authentication);
		}
	}

	private void writeJson(HttpServletResponse response, String msg) throws IOException {
		response.setCharacterEncoding(StandardCharsets.UTF_8.name());
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setStatus(HttpStatus.SC_UNAUTHORIZED);
		Map<String, Object> params = new HashMap<String, Object>();
		params.put("msg", msg);
		response.getWriter().print(OBJECT_MAPPER.writeValueAsString(params));
	}
}
