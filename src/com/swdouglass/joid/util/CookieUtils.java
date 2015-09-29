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
package com.swdouglass.joid.util;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 
 */
public class CookieUtils {

  /** Default age is 30 days */
  private static final int DEFAULT_AGE = 60 * 60 * 24 * 30;

  /**
   * Sets the cookie
   * @param response
   * @param cookieName
   * @param value
   */
  public static void setCookie(HttpServletResponse response, String cookieName,
    String value) {
    Cookie cookie = new Cookie(cookieName, value);
    cookie.setMaxAge(DEFAULT_AGE);
    response.addCookie(cookie);
  }

  /**
   * Returns the value of the cookie specified by cookieName or defaultValue if
   * Cookie does not exist.
   *
   * @param request
   * @param cookieName
   * @param defaultValue
   * @return
   */
  public static String getCookieValue(HttpServletRequest request, String cookieName,
    String defaultValue) {
    Cookie cookie = getCookie(request, cookieName);
    if (cookie == null) {
      return defaultValue;
    } else {
      return cookie.getValue();
    }
  }

  public static Cookie getCookie(HttpServletRequest request, String cookieName) {
    Cookie[] cookies = request.getCookies();
    if (cookies == null) {
      return null;
    }
    for (int i = 0; i < cookies.length; i++) {
      Cookie cookie = cookies[i];
      if (cookieName.equals(cookie.getName())) {
        return cookie;
      }
    }
    return null;
  }
}
