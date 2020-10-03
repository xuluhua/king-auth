package com.auth.authenorize;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityMetadataSource;
import org.springframework.security.access.event.AuthenticationCredentialsNotFoundEvent;
import org.springframework.security.access.event.AuthorizationFailureEvent;
import org.springframework.security.access.event.AuthorizedEvent;
import org.springframework.security.access.event.PublicInvocationEvent;
import org.springframework.security.access.intercept.AfterInvocationManager;
import org.springframework.security.access.intercept.InterceptorStatusToken;
import org.springframework.security.access.intercept.RunAsManager;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;

public abstract class CustomSecurityInterceptor
		implements InitializingBean, ApplicationEventPublisherAware, MessageSourceAware {

	protected final Log logger = LogFactory.getLog(getClass());

	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

	private ApplicationEventPublisher eventPublisher;

	@Autowired
	private CustomAccessDecisionManager accessDecisionManager;

	private AfterInvocationManager afterInvocationManager;

	private AuthenticationManager authenticationManager = new NoOpAuthenticationManager();

	private RunAsManager runAsManager = new CustomNullRunAsManager();

	private boolean alwaysReauthenticate = false;
	private boolean rejectPublicInvocations = false;
	private boolean validateConfigAttributes = true;
	private boolean publishAuthorizationSuccess = false;

	@Override
	public void setMessageSource(MessageSource messageSource) {
		this.messages = new MessageSourceAccessor(messageSource);
	}

	@Override
	public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
		this.eventPublisher = applicationEventPublisher;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(getSecureObjectClass(), "Subclass must provide a non-null response to getSecureObjectClass()");
		Assert.notNull(this.messages, "A message source must be set");
		Assert.notNull(this.authenticationManager, "An AuthenticationManager is required");
		Assert.notNull(this.accessDecisionManager, "An CustomAccessDecisionManager is required");
		Assert.notNull(this.runAsManager, "A RunAsManager is required");
		Assert.notNull(this.obtainSecurityMetadataSource(), "An CustomSecurityMetadataSource is required");
		Assert.isTrue(this.obtainSecurityMetadataSource().supports(getSecureObjectClass()),
				() -> "SecurityMetadataSource does not support secure object class: " + getSecureObjectClass());
		Assert.isTrue(this.runAsManager.supports(getSecureObjectClass()),
				() -> "RunAsManager does not support secure object class: " + getSecureObjectClass());
		Assert.isTrue(this.accessDecisionManager.supports(getSecureObjectClass()),
				() -> "CustomAccessDecisionManager does not support secure object class: " + getSecureObjectClass());

		if (this.afterInvocationManager != null) {
			Assert.isTrue(this.afterInvocationManager.supports(getSecureObjectClass()),
					() -> "AfterInvocationManager does not support secure object class: " + getSecureObjectClass());
		}

		if (this.validateConfigAttributes) {
			Collection<ConfigAttribute> attributeDefs = this.obtainSecurityMetadataSource().getAllConfigAttributes();
			if (attributeDefs == null) {
				logger.warn("Could not validate configuration attributes as the SecurityMetadataSource did not return "
						+ "any attributes from getAllConfigAttributes()");
				return;
			}

			Set<ConfigAttribute> unsupportedAttrs = new HashSet<ConfigAttribute>();
			for (ConfigAttribute attr : attributeDefs) {
				if (!this.runAsManager.supports(attr) && !this.accessDecisionManager.supports(attr)
						&& ((this.afterInvocationManager == null) || !this.afterInvocationManager.supports(attr))) {
					unsupportedAttrs.add(attr);
				}
			}
			if (unsupportedAttrs.size() != 0) {
				throw new IllegalArgumentException("Unsupported configuration attributes: " + unsupportedAttrs);
			}
			logger.debug("Validated configuration attributes");
		}
	}

	protected InterceptorStatusToken beforeInvocation(Object object) {
		Assert.notNull(object, "Object was null");
		final boolean debug = logger.isDebugEnabled();

		if (!getSecureObjectClass().isAssignableFrom(object.getClass())) {
			throw new IllegalArgumentException("Security invocation attempted for object " + object.getClass().getName()
					+ " but CustomSecurityInterceptor only configured to support secure objects of type: "
					+ getSecureObjectClass());
		}
		Collection<ConfigAttribute> attributes = this.obtainSecurityMetadataSource().getAttributes(object);
		if (attributes == null || attributes.isEmpty()) {
			if (rejectPublicInvocations) {
				throw new IllegalArgumentException("Secure object invocation " + object
						+ " was denied as public invocations are not allowed via this interceptor. "
						+ "This indicates a configuration error because the "
						+ "rejectPublicInvocations property is set to 'true'");
			}

			if (debug) {
				logger.debug("Public object - authentication not attempted");
			}

			publishEvent(new PublicInvocationEvent(object));
			throw new AccessDeniedException("没有权限");
		}

		if (debug) {
			logger.debug("Secure object: " + object + "; Attributes: " + attributes);
		}

		if (SecurityContextHolder.getContext().getAuthentication() == null) {
			credentialsNotFound(messages.getMessage("CustomSecurityInterceptor.authenticationNotFound",
					"An Authentication object was not found in the SecurityContext"), object, attributes);
		}

		Authentication authenticated = authenticateIfRequired();

		// Attempt authorization
		try {
			this.accessDecisionManager.decide(authenticated, object, attributes);
		} catch (AccessDeniedException accessDeniedException) {
			publishEvent(new AuthorizationFailureEvent(object, attributes, authenticated, accessDeniedException));
			throw accessDeniedException;
		}
		if (debug) {
			logger.debug("Authorization successful");
		}

		if (publishAuthorizationSuccess) {
			publishEvent(new AuthorizedEvent(object, attributes, authenticated));
		}

		// Attempt to run as a different user
		Authentication runAs = this.runAsManager.buildRunAs(authenticated, object, attributes);

		if (runAs == null) {
			if (debug) {
				logger.debug("RunAsManager did not change Authentication object");
			}
			return new InterceptorStatusToken(SecurityContextHolder.getContext(), false, attributes, object);
		} else {
			if (debug) {
				logger.debug("Switching to RunAs Authentication: " + runAs);
			}
			SecurityContext origCtx = SecurityContextHolder.getContext();
			SecurityContextHolder.setContext(SecurityContextHolder.createEmptyContext());
			SecurityContextHolder.getContext().setAuthentication(runAs);

			// need to revert to token.Authenticated post-invocation
			return new InterceptorStatusToken(origCtx, true, attributes, object);
		}
	}

	protected void finallyInvocation(InterceptorStatusToken token) {

		if (token != null && token.isContextHolderRefreshRequired()) {
			if (logger.isDebugEnabled()) {
				logger.debug("Reverting to original Authentication: " + token.getSecurityContext().getAuthentication());
			}

			SecurityContextHolder.setContext(token.getSecurityContext());
		}
	}

	protected Object afterInvocation(InterceptorStatusToken token, Object returnObject) {

		if (token == null) {
			return returnObject;
		}
		finallyInvocation(token);
		if (afterInvocationManager != null) {
			try {
				returnObject = afterInvocationManager.decide(token.getSecurityContext().getAuthentication(),
						token.getSecureObject(), token.getAttributes(), returnObject);
			} catch (AccessDeniedException accessDeniedException) {
				AuthorizationFailureEvent event = new AuthorizationFailureEvent(token.getSecureObject(),
						token.getAttributes(), token.getSecurityContext().getAuthentication(), accessDeniedException);

				publishEvent(event);

				throw accessDeniedException;
			}
		}
		return returnObject;
	}

	private Authentication authenticateIfRequired() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

		if (authentication.isAuthenticated() && !alwaysReauthenticate) {
			if (logger.isDebugEnabled()) {
				logger.debug("Previously Authenticated: " + authentication);
			}
			return authentication;
		}

		authentication = authenticationManager.authenticate(authentication);

		// We don't authenticated.setAuthentication(true), because each provider should
		// do
		// that
		if (logger.isDebugEnabled()) {
			logger.debug("Successfully Authenticated: " + authentication);
		}

		SecurityContextHolder.getContext().setAuthentication(authentication);

		return authentication;
	}

	private void credentialsNotFound(String reason, Object secureObject, Collection<ConfigAttribute> configAttributes) {

		AuthenticationCredentialsNotFoundException exception = new AuthenticationCredentialsNotFoundException(reason);

		AuthenticationCredentialsNotFoundEvent event = new AuthenticationCredentialsNotFoundEvent(secureObject,
				configAttributes, exception);

		publishEvent(event);
		throw exception;
	}

	public MessageSourceAccessor getMessages() {
		return messages;
	}

	public void setMessages(MessageSourceAccessor messages) {
		this.messages = messages;
	}

	public ApplicationEventPublisher getEventPublisher() {
		return eventPublisher;
	}

	public void setEventPublisher(ApplicationEventPublisher eventPublisher) {
		this.eventPublisher = eventPublisher;
	}

	public AccessDecisionManager getAccessDecisionManager() {
		return accessDecisionManager;
	}

	public void setAccessDecisionManager(CustomAccessDecisionManager accessDecisionManager) {
		this.accessDecisionManager = accessDecisionManager;
	}

	public AfterInvocationManager getAfterInvocationManager() {
		return afterInvocationManager;
	}

	public void setAfterInvocationManager(AfterInvocationManager afterInvocationManager) {
		this.afterInvocationManager = afterInvocationManager;
	}

	public AuthenticationManager getAuthenticationManager() {
		return authenticationManager;
	}

	public void setAuthenticationManager(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	public RunAsManager getRunAsManager() {
		return runAsManager;
	}

	public void setRunAsManager(RunAsManager runAsManager) {
		this.runAsManager = runAsManager;
	}

	public abstract Class<?> getSecureObjectClass();

	public boolean isAlwaysReauthenticate() {
		return alwaysReauthenticate;
	}

	public void setAlwaysReauthenticate(boolean alwaysReauthenticate) {
		this.alwaysReauthenticate = alwaysReauthenticate;
	}

	public boolean isRejectPublicInvocations() {
		return rejectPublicInvocations;
	}

	public void setRejectPublicInvocations(boolean rejectPublicInvocations) {
		this.rejectPublicInvocations = rejectPublicInvocations;
	}

	public boolean isValidateConfigAttributes() {
		return validateConfigAttributes;
	}

	public abstract SecurityMetadataSource obtainSecurityMetadataSource();

	public void setValidateConfigAttributes(boolean validateConfigAttributes) {
		this.validateConfigAttributes = validateConfigAttributes;
	}

	private void publishEvent(ApplicationEvent event) {
		if (this.eventPublisher != null) {
			this.eventPublisher.publishEvent(event);
		}
	}

	public boolean isPublishAuthorizationSuccess() {
		return publishAuthorizationSuccess;
	}

	public void setPublishAuthorizationSuccess(boolean publishAuthorizationSuccess) {
		this.publishAuthorizationSuccess = publishAuthorizationSuccess;
	}

	private static class NoOpAuthenticationManager implements AuthenticationManager {

		@Override
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			throw new AuthenticationServiceException("Cannot authenticate " + authentication);
		}

	}

}
