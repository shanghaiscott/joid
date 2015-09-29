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
package com.swdouglass.joid.server;

import org.apache.commons.logging.LogFactory;
import org.apache.commons.logging.Log;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLDecoder;

/**
 * 
 */
public class UserUrlFilter implements Filter {

  private static Log log = LogFactory.getLog(UserUrlFilter.class);
  private String idJsp;

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    idJsp = filterConfig.getInitParameter("idJsp");
  }

  @Override
  public void doFilter(ServletRequest req, ServletResponse res,
    FilterChain filterChain) throws IOException, ServletException {
    HttpServletRequest request = (HttpServletRequest) req;
    HttpServletResponse response = (HttpServletResponse) res;

    String s = request.getServletPath();
    s = URLDecoder.decode(s, "utf-8");
    log.debug("servletpath: " + s);
    String[] sections = s.split("/");
    log.debug("sections.length: " + sections.length);
    String contextPath = request.getContextPath();
    if (sections.length >= 2) {
      for (int i = 0; i < sections.length; i++) {
        String section = sections[i];
        log.debug("section: " + section);
        if (section.equals("user")) {
          String username = sections[i + 1];
          log.debug("username: " + username);
          log.debug("forwarding to: " + contextPath + idJsp);
          request.setAttribute("username", username);
          forward(request, response, idJsp);
          return;
        }
      }

    }
    filterChain.doFilter(req, res);
  }

  @Override
  public void destroy() {
  }

  private void forward(HttpServletRequest request, HttpServletResponse response,
    String path)
    throws IOException, ServletException {
    request.getRequestDispatcher(path).forward(request, response);
  }
}
