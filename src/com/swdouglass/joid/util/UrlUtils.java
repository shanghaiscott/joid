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

import javax.servlet.http.HttpServletRequest;

/**
 * User: treeder
 * Date: Jul 19, 2007
 * Time: 4:05:35 PM
 */
public class UrlUtils {

  public static String getFullUrl(HttpServletRequest request) {
    StringBuilder b = getServletUrl(request);
    String queryString = request.getQueryString();
    if (queryString != null) {
      b.append("?").append(queryString);
    }
    return b.toString();
  }

  public static StringBuilder getServletUrl(HttpServletRequest request) {
    StringBuilder b = new StringBuilder(getBaseUrl(request));
    String servletPath = request.getServletPath();
    if (servletPath != null) {
      b.append(servletPath);
    }
    return b;
  }

  /**
   *
   * @param request
   * @return the url of the local host including the context, not including a trailing "/"
   * // TODO: make these return StringBuilder instead
   */
  public static String getBaseUrl(HttpServletRequest request) {
    StringBuilder b = new StringBuilder();
    b.append(getHostUrl(request));
    String context = request.getContextPath();
    if (context != null) {
      b.append(context);
    }
    return b.toString();
  }

  /**
   *
   * @param request
   * @return the host url without the context
   * // TODO: make these return StringBuilder instead
   */
  public static String getHostUrl(HttpServletRequest request) {
    String scheme = request.getScheme();
    String serverName = request.getServerName();
    String port = request.getServerPort() == 80 ||
      request.getServerPort() == 443 ? "" : ":" + request.getServerPort();
    StringBuilder start = new StringBuilder();
    start.append(scheme);
    start.append("://");
    start.append(serverName);
    start.append(port);
    return start.toString();
  }
}
