package com.auth.jwt;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class JWTUtils {

	private static final Logger LOGGER = LoggerFactory.getLogger(JWTUtils.class);

	private static final String TOKEN_PREFIX = "Bearer ";

	private static final String SUBJECT = "king";

	private static final long EXPIRITION = 1000 * 24 * 60 * 60 * 7;

	private static final String APPSECRET_KEY = "king_secret";

	public static final String USERNAME_PARAMETER = "username";

	/**
	 * 从数据声明生成令牌
	 *
	 * @param claims 数据声明
	 * @return 令牌
	 */
	public static String generateJsonWebToken(Map<String, Object> claims) {
		long now = System.currentTimeMillis();
		return TOKEN_PREFIX + Jwts.builder().setClaims(claims).setIssuer("king").setSubject(SUBJECT).setAudience("king")
				.setExpiration(new Date(now + EXPIRITION)).setNotBefore(new Date(now)).setIssuedAt(new Date(now))
				.setId(UUID.randomUUID().toString()).signWith(SignatureAlgorithm.HS256, APPSECRET_KEY).compact();
	}

	/**
	 * 从数据声明生成令牌
	 * 
	 * @param userDetails 用户
	 * @return 令牌
	 */
	public static String generateJsonWebToken(UserDetails userDetails) {
		if (StringUtils.isEmpty(userDetails.getUsername())) {
			return null;
		}
		Map<String, Object> claims = new HashMap<String, Object>();
		claims.put(USERNAME_PARAMETER, userDetails.getUsername());
		claims.put("created", new Date());
		return generateJsonWebToken(claims);
	}

	/**
	 * 从数据声明生成令牌
	 * 
	 * @param username 用户名
	 * @return 令牌
	 */
	public static String generateJsonWebToken(String username) {
		if (StringUtils.isEmpty(username)) {
			return null;
		}
		Map<String, Object> claims = new HashMap<String, Object>(2);
		claims.put(USERNAME_PARAMETER, username);
		claims.put("created", new Date());
		return generateJsonWebToken(claims);
	}

	/**
	 * 验证令牌
	 * 
	 * @param token       令牌
	 * @param userDetails 用户
	 * @return 是否有效
	 */
	public static Boolean validateToken(String token, UserDetails userDetails) {
		if (isTokenExpired(token)) {
			return false;
		}
		return getUsernameFromToken(token).equals(userDetails.getUsername());
	}

	/**
	 * 从令牌中获取数据声明
	 *
	 * @param token 令牌
	 * @return 数据声明
	 */
	public static Claims getClaimsFromToken(String token) {
		Claims claims;
		token = StringUtils.substringAfter(token, TOKEN_PREFIX);
		try {
			claims = Jwts.parser().setSigningKey(APPSECRET_KEY).parseClaimsJws(token).getBody();
		} catch (Exception e) {
			claims = null;
			LOGGER.info("JWT格式验证失败：{}", token);
		}
		return claims;
	}

	/**
	 * 从令牌中获取用户名
	 *
	 * @param token 令牌
	 * @return 用户名
	 */
	public static String getUsernameFromToken(String token) {
		String username = null;
		try {
			Claims claims = getClaimsFromToken(token);
			username = (String) claims.get(USERNAME_PARAMETER);
		} catch (Exception e) {
			LOGGER.error("无法获取 username;{}", token);
		}
		return username;
	}

	/**
	 * 判断令牌是否过期
	 *
	 * @param token 令牌
	 * @return 是否过期
	 */
	public static Boolean isTokenExpired(String token) {
		try {
			Claims claims = getClaimsFromToken(token);
			Date expriation = claims.getExpiration();
			return expriation.before(new Date());
		} catch (Exception e) {
			return false;
		}
	}

	/**
	 * 刷新令牌
	 * 
	 * @param token 令牌
	 * @return 令牌
	 */
	public static String refreshToken(String token) {
		String refreshToken;
		try {
			Claims claims = getClaimsFromToken(token);
			claims.put("created", new Date());
			refreshToken = generateJsonWebToken(claims);
		} catch (Exception e) {
			refreshToken = null;
		}
		return refreshToken;
	}
}
