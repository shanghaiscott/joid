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

import com.swdouglass.joid.AuthenticationRequest;
import com.swdouglass.joid.Crypto;
import com.swdouglass.joid.MessageFactory;
import com.swdouglass.joid.OpenId;
import com.swdouglass.joid.OpenIdException;
import com.swdouglass.joid.ServerInfo;
import com.swdouglass.joid.Store;
import com.swdouglass.joid.util.CookieUtils;
import com.swdouglass.joid.util.DependencyUtils;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Enumeration;
import java.util.Map;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * 
 */
public class OpenIdServlet extends HttpServlet {

  private static Log log = LogFactory.getLog(OpenIdServlet.class);
  private static final long serialVersionUID = 297366254782L;

  // Public for use by login.jsp
  public static final String USERNAME_ATTRIBUTE = "username";
  public static final String USER_ATTRIBUTE = "user";
  // Public for access by CookieUtil
  public static final String COOKIE_AUTH_NAME = "authKey";
  public static final String COOKIE_USERNAME = "username";
  // Servlet Init Params (set in web.xml)
  private static final String INIT_STORE_CLASS="storeClassName";
  private static final String INIT_STORE_CLASS_DEFAULT="com.swdouglass.joid.store.MemoryStoreImpl";
  private static final String INIT_USER_CLASS="userManagerClassName";
  private static final String INIT_USER_CLASS_DEFAULT="com.swdouglass.joid.server.MemoryUserManagerImpl";
  public static final String INIT_CAPTCHA_PRIVATE_KEY="captchaPrivateKey";// Public for use by login.jsp
  private static final String INIT_LOGIN_PAGE="loginPage";
  private static final String INIT_LOGIN_PAGE_DEFAULT="login.jsp";
  private static final String INIT_ENDPOINT_URL="endPointURL";
  // OpenID parameters
  private static final String ID_CLAIMED = "idClaimed";
  private static final String QUERY = "query";

  private static UserManager userManager;
  private static OpenId openId;

  private String captchaPrivateKey;
  private String loginPage;
  private Store store;
  private Crypto crypto;
  

  @Override
  public void init(ServletConfig config) throws ServletException {
    super.init(config);
    String storeClassName = 
      (config.getInitParameter(INIT_STORE_CLASS) == null ?
        INIT_STORE_CLASS_DEFAULT : config.getInitParameter(INIT_STORE_CLASS));
    String userManagerClassName = 
      (config.getInitParameter(INIT_USER_CLASS) == null ?
        INIT_USER_CLASS_DEFAULT : config.getInitParameter(INIT_USER_CLASS));
    this.loginPage = (config.getInitParameter(INIT_LOGIN_PAGE) == null ?
      INIT_LOGIN_PAGE_DEFAULT : config.getInitParameter(INIT_LOGIN_PAGE));
    this.captchaPrivateKey = config.getInitParameter(INIT_CAPTCHA_PRIVATE_KEY);

    String endPointUrl = config.getInitParameter(INIT_ENDPOINT_URL);

    this.store = Store.getInstance(storeClassName);
    this.store.setAssociationLifetime(600);
    OpenIdServlet.userManager = (UserManager) DependencyUtils.newInstance(userManagerClassName);
    this.crypto = new Crypto();
    OpenIdServlet.openId = new OpenId(new ServerInfo(endPointUrl, store, crypto));
  }

  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response)
  throws ServletException, IOException {
    doQuery(request.getQueryString(), request, response);
  }

  @Override
  public void doPost(HttpServletRequest request, HttpServletResponse response)
  throws ServletException, IOException {
    StringBuilder sb = new StringBuilder();
    Enumeration e = request.getParameterNames();
    while (e.hasMoreElements()) {
      String name = (String) e.nextElement();
      String[] values = request.getParameterValues(name);
      if (values.length == 0) {
        throw new IOException("Empty value not allowed: " + name + " has no value");
      }
      try {
        sb.append(URLEncoder.encode(name, "UTF-8") + "=" + URLEncoder.encode(values[0], "UTF-8"));
      } catch (UnsupportedEncodingException ex) {
        throw new IOException(ex.toString());
      }
      if (e.hasMoreElements()) {
        sb.append("&");
      }
    }
    doQuery(sb.toString(), request, response);
  }

  public void doQuery(String query, HttpServletRequest request, HttpServletResponse response)
  throws ServletException, IOException {
    debug("\nrequest\n-------\n" + query + "\n");
    
    if (!(openId.canHandle(query))) {
      returnError(query, response);
      return;
    }
    try {
      boolean isAuth = openId.isAuthenticationRequest(query);
      HttpSession session = request.getSession(true);
      String username = getLoggedIn(request);
      debug("[OpenIdServlet] Logged in as: " + username);

      if (this.captchaPrivateKey != null) {
        session.setAttribute(INIT_CAPTCHA_PRIVATE_KEY, this.captchaPrivateKey);
      }
      if (request.getParameter(AuthenticationRequest.OPENID_TRUST_ROOT) != null) {
        session.setAttribute(AuthenticationRequest.OPENID_TRUST_ROOT,
          request.getParameter(AuthenticationRequest.OPENID_TRUST_ROOT));
      }
      if (request.getParameter(AuthenticationRequest.OPENID_RETURN_TO) != null) {
        session.setAttribute(AuthenticationRequest.OPENID_RETURN_TO,
          request.getParameter(AuthenticationRequest.OPENID_RETURN_TO));
      }
      // If we're handling an authentication request, and the user has not been authenticated,
      // redirect to the login page.
      if (isAuth && username == null) {
        // TODO: should ask user to accept realm even if logged in, but only once
        // ask user to accept this realm
        request.setAttribute(QUERY, query);
        String realm = request.getParameter(AuthenticationRequest.OPENID_REALM);
        if (realm == null) {
          realm = request.getParameter(AuthenticationRequest.OPENID_RETURN_TO);
        }
        request.setAttribute(AuthenticationRequest.OPENID_REALM, realm);
        session.setAttribute(QUERY, query);
        //if claimed_id is null then use identity instead (because of diffs between v2 & v1 of spec)
        if (request.getParameter(AuthenticationRequest.OPENID_CLAIMED_ID) == null) {
          session.setAttribute(AuthenticationRequest.OPENID_CLAIMED_ID,
            request.getParameter(AuthenticationRequest.OPENID_IDENTITY));
        } else {
          session.setAttribute(AuthenticationRequest.OPENID_CLAIMED_ID,
            request.getParameter(AuthenticationRequest.OPENID_CLAIMED_ID));
        }
        session.setAttribute(AuthenticationRequest.OPENID_REALM,
          request.getParameter(AuthenticationRequest.OPENID_REALM));
        response.sendRedirect(loginPage);
        return;
      }
      String s = openId.handleRequest(query);
      debug("\nresponse\n--------\n" + s + "\n");
      if (isAuth) {
        AuthenticationRequest authReq = (AuthenticationRequest) MessageFactory.parseRequest(query);
        //String claimedId = (String) session.getAttribute(ID_CLAIMED);
        /*TODO: Ensure that the previously claimed id is the same as the just
        passed in claimed id. */
        String identity;
        if (request.getParameter(AuthenticationRequest.OPENID_CLAIMED_ID) == null) {
          identity = request.getParameter(AuthenticationRequest.OPENID_IDENTITY);
        } else {
          identity = authReq.getClaimedIdentity();
        }
        User user = (User) session.getAttribute(USER_ATTRIBUTE);
        debug("User.username: " + user);
        debug("identity: " + identity);
        if (getUserManager().canClaim(user, identity)) {
          //String returnTo = authReq.getReturnTo();
          String returnTo = (String) session.getAttribute(AuthenticationRequest.OPENID_RETURN_TO);
          String delim = (returnTo.indexOf('?') >= 0) ? "&" : "?";
          s = response.encodeRedirectURL(returnTo + delim + s);
          debug("sending redirect to: " + s);
          response.sendRedirect(s);
        } else {
          throw new OpenIdException("User cannot claim this id.");
        }

      } else {
        // Association request
        int len = s.length();
        PrintWriter out = response.getWriter();
        response.setHeader("Content-Length", Integer.toString(len));
        if (openId.isAnErrorResponse(s)) {
          response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        }
        out.print(s);
        out.flush();
      }
    } catch (OpenIdException e) {
      e.printStackTrace();
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e.getMessage());
    }
  }

  /**
   *
   * @param request
   * @return Username the user is logged in as
   */
  public static String getLoggedIn(HttpServletRequest request) {
    String o = (String) request.getSession(true).getAttribute(USERNAME_ATTRIBUTE);
    if (o != null) {
      return o;
    }
    // check Remember Me cookies
    String authKey = CookieUtils.getCookieValue(request, COOKIE_AUTH_NAME, null);
    if (authKey != null) {
      String username = CookieUtils.getCookieValue(request, COOKIE_USERNAME, null);
      if (username != null) {
        // lets check the UserManager to make sure this is a valid match
        o = getUserManager().getRememberedUser(username, authKey);
        if (o != null) {
          request.getSession(true).setAttribute(USERNAME_ATTRIBUTE, o);
        }
      }
    }
    return o;
  }

  /**
   *
   * @param request
   * @param username if null, will logout
   */
  public static void setLoggedIn(HttpServletRequest request, String username) {
    request.getSession(true).setAttribute(USERNAME_ATTRIBUTE, username);
  }

  private void returnError(String query, HttpServletResponse response)
  throws ServletException, IOException {
    Map map = MessageFactory.parseQuery(query);
    String returnTo = (String) map.get("openid.return_to");
    boolean goodReturnTo = false;
    try {
      URL url = new URL(returnTo);
      goodReturnTo = true;
    } catch (MalformedURLException e) {
      e.printStackTrace();
    }

    if (goodReturnTo) {
      String s = "?openid.ns:http://specs.openid.net/auth/2.0" + "&openid.mode=error&openid.error=BAD_REQUEST";
      s = response.encodeRedirectURL(returnTo + s);
      response.sendRedirect(s);
    } else {
      PrintWriter out = response.getWriter();
      // response.setContentLength() seems to be broken,
      // so set the header manually
      String s = "ns:http://specs.openid.net/auth/2.0\n" + "&mode:error" + "&error:BAD_REQUEST\n";
      int len = s.length();
      response.setHeader("Content-Length", Integer.toString(len));
      response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
      out.print(s);
      out.flush();
    }
  }

  private void debug(String message) {
    if (log.isDebugEnabled()) {
      log.debug(message);
    }
  }

  /**
   * This sets a session variable stating that the claimed_id for this request
   * has been verified so we can now return back to the relying party.
   *
   * @param session
   * @param claimedId
   */
  public static void idClaimed(HttpSession session, String claimedId) {
    session.setAttribute(ID_CLAIMED, claimedId);
  }

  public static UserManager getUserManager() {
    return userManager;
  }
}
