package ch.fuchsnet.spring;

import com.atlassian.bitbucket.auth.ExpiredAuthenticationException;
import com.atlassian.bitbucket.auth.HttpAuthenticationContext;
import com.atlassian.bitbucket.auth.HttpAuthenticationHandler;
import com.atlassian.bitbucket.auth.HttpAuthenticationSuccessContext;
import com.atlassian.bitbucket.auth.HttpAuthenticationSuccessHandler;
import com.atlassian.bitbucket.i18n.I18nService;
import com.atlassian.bitbucket.user.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import java.io.IOException;

/*
Remote User Single Sign On Authenticator russo-bitbucket: 
Authenticating to BitBucket Server with the X_Forwarded_User HTTP header
Copyright (C) 2014  Christian Loosli

Loosely based on the example by Michael Heemskerk available at
https://bitbucket.org/mheemskerk/stash-auth-plugin-example

This software may be modified and distributed under the terms
of the MIT license.  See the COPYING file for details.
*/

/**
 * Implementation of HttpAuthenticationHandler that uses the Apache set
 * X-Forwarded-User header in a HTTPRequest object for single sign on.
 *
 */
public class RussoBitBucketAuthenticationHandler implements
		HttpAuthenticationHandler, HttpAuthenticationSuccessHandler
{

	private static final String strKeyContainerAuthName = "auth.container.remote-user";
    private static final Logger log = LoggerFactory.getLogger(RussoBitBucketAuthenticationHandler.class);

	// Header we read. Has to be lowercase even if the header is set uppercase
	// in apache
	private static final String strHeaderName = "x-forwarded-user";

	// Print additional information and warnings, useful when developing, else
	// it just spams the logs a bit.
	private static final boolean useDebug = false;

	private final I18nService i18nService;
	private final UserService userService;

	public RussoBitBucketAuthenticationHandler(I18nService i18nService,
			UserService userService)
	{
		this.i18nService = i18nService;
		this.userService = userService;
	}

	@Override
	public ApplicationUser authenticate(HttpAuthenticationContext httpAuthenticationContext)
	{
		HttpServletRequest request = httpAuthenticationContext.getRequest();

		String forwardedUser = request.getHeader(strHeaderName);

		if (forwardedUser == null || forwardedUser.isEmpty())
		{
			if (useDebug)
			{
				log.info("Header " + strHeaderName + " was empty / not set");
			}
			return null;
		}

		if (useDebug)
		{
			log.info("Got user: " + forwardedUser);
		}

		ApplicationUser user = userService.getUserByName(forwardedUser);

		if (user != null)
		{
			request.setAttribute(strKeyContainerAuthName, forwardedUser);
		}
		else
		{
			log.error("User " + request.getHeader(strHeaderName) + " not found.");
		}

		return user;
	}

	@Override
	public void validateAuthentication(HttpAuthenticationContext httpAuthenticationContext)
	{
		HttpSession session = httpAuthenticationContext.getRequest().getSession(false);
		
		if (session == null)
		{
			return;
		}

		String sessionUser = (String) session.getAttribute(strKeyContainerAuthName);
		String forwardedUser = httpAuthenticationContext.getRequest().getHeader(strHeaderName);

		if (sessionUser != null && !sessionUser.equals(forwardedUser))
		{
			throw new ExpiredAuthenticationException(i18nService.getKeyedText("container.auth.usernamenomatch",
                    "Session username '{0}' does not match username provided by the container '{1}'",
                    sessionUser, forwardedUser));
		}
	}

	@Override
	public boolean onAuthenticationSuccess(HttpAuthenticationSuccessContext context)
			throws ServletException, IOException
	{

		String authUser = (String) context.getRequest().getAttribute(strKeyContainerAuthName);
		if (authUser != null)
		{
			context.getRequest().getSession().setAttribute(strKeyContainerAuthName, authUser);
			if (useDebug)
			{
				log.info("Added " + authUser + " as " + strKeyContainerAuthName + " to session.");
			}
		}
		else
		{
			if (useDebug)
			{
				log.warn("Request " + strKeyContainerAuthName + " was not set / null.");
			}
		}

		return false;
	}
}
