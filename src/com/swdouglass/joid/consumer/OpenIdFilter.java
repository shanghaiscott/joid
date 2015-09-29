/*
 * MODIFICATIONS to the original source have been made by
 * Scott Douglass <scott@swdouglass.com>
 *
 * Copyright 2009 Scott Douglass <scott@swdouglass.com>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * The original copyright notice and license terms are below.
 */
package com.swdouglass.joid.consumer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import com.swdouglass.joid.OpenIdRuntimeException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This filter will log a user in automatically if it sees the required openid
 * parameters in the request.
 *
 */
public class OpenIdFilter implements Filter {

  private static Log log = LogFactory.getLog(OpenIdFilter.class);
  private static JoidConsumer joid = new JoidConsumer();
  public static final String OPENID_ATTRIBUTE = "openid.identity";
  boolean saveIdentityUrlAsCookie = false;
  private String cookieDomain;
  private List<String> ignorePaths = new ArrayList<String>();
  private static boolean configuredProperly = false;
  private Integer cookieMaxAge;

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    log.info("init OpenIdFilter");
    String saveInCookie = filterConfig.getInitParameter("saveInCookie");
    if (saveInCookie != null) {
      saveIdentityUrlAsCookie = Boolean.parseBoolean(saveInCookie);
      log.debug("saving identities in cookie: " + saveIdentityUrlAsCookie);
    }
    cookieDomain = filterConfig.getInitParameter("cookieDomain");
    String cookieMaxAgeString = filterConfig.getInitParameter("cookieMaxAge");
    if (cookieMaxAgeString != null) {
      cookieMaxAge = Integer.valueOf(cookieMaxAgeString);
    }
    String _ignorePaths = filterConfig.getInitParameter("ignorePaths");
    if (_ignorePaths != null) {
      String paths[] = _ignorePaths.split(",");
      for (int i = 0; i < paths.length; i++) {
        String path = paths[i].trim();
        this.ignorePaths.add(path);
      }
    }
    configuredProperly = true;
    log.debug("end init OpenIdFilter");
  }

  /**
   * This is to check to make sure the OpenIdFilter is setup propertly in the
   * web.xml.
   */
  private static void ensureFilterConfiguredProperly() {
    if (!configuredProperly) {
      throw new OpenIdRuntimeException(
        "OpenIdFilter Not Configured Properly! " +
        "Check your web.xml for OpenIdFilter.");
    }
  }

  @Override
  public void doFilter(ServletRequest servletRequest,
    ServletResponse servletResponse,
    FilterChain filterChain) throws IOException, ServletException {
    // basically just check for openId parameters
    HttpServletRequest request = (HttpServletRequest) servletRequest;
    if (servletRequest.getParameter(OPENID_ATTRIBUTE) != null 
      && !ignored (request)) {
      try {
        @SuppressWarnings("unchecked")
        AuthenticationResult result = joid.authenticate(
          convertToStringValueMap(servletRequest.getParameterMap()));
        String identity = result.getIdentity();
        if (identity != null) {
          HttpServletRequest req = (HttpServletRequest) servletRequest;
          req.getSession(true).setAttribute(OpenIdFilter.OPENID_ATTRIBUTE,
            identity);
          HttpServletResponse resp = (HttpServletResponse) servletResponse; // could check this before setting
          Cookie cookie = new Cookie(OPENID_ATTRIBUTE, identity);
          if (cookieDomain != null) {
            cookie.setDomain(cookieDomain);
          }
          if (cookieMaxAge != null) {
            cookie.setMaxAge(cookieMaxAge);
          }
          resp.addCookie(cookie);
          // redirect to get rid of the long url
          resp.sendRedirect(result.getResponse().getReturnTo());
          return;
        }
      } catch (AuthenticationException e) {
        e.printStackTrace();
        log.info("auth failed: " + e.getMessage());
      // should this be handled differently?
      } catch (Exception e) {
        e.printStackTrace();
      }
    }
    filterChain.doFilter(servletRequest, servletResponse);
  }

  private boolean ignored(HttpServletRequest request) {
    String servletPath = request.getServletPath();
    for (int i = 0; i < ignorePaths.size(); i++) {
      String s = ignorePaths.get(i);
      if (servletPath.startsWith(s)) {
        return true;
      }
    }
    return false;
  }

  public static void logout(HttpSession session) {
    session.removeAttribute(OPENID_ATTRIBUTE);
  }

  private Map<String, String> convertToStringValueMap(
    Map<String, String[]> parameterMap) {
    Map<String, String> ret = new HashMap<String, String>();
    for (Map.Entry mapEntry : parameterMap.entrySet()) {
      String key = (String) mapEntry.getKey();
      String[] value = (String[]) mapEntry.getValue();
      ret.put(key, value[0]);
    }
    return ret;
  }

  @Override
  public void destroy() {
  }

  public static JoidConsumer joid() {
    return joid;
  }

  public static String getCurrentUser(HttpSession session) {
    ensureFilterConfiguredProperly();
    String openid = (String) session.getAttribute(OpenIdFilter.OPENID_ATTRIBUTE);
    if (openid != null) {
      return openid;
    }
    // TODO: THIS COOKIE THING CAN'T WORK BECAUSE SOMEONE COULD FAKE IT, NEEDS AN AUTH TOKEN ALONG WITH IT
    return openid;
  }
}
