<%--
This page is a sample login page for OpenID SERVERS.
You only need this if you are an OpenID provider.
Consumers do NOT need this page.
--%>
<%@ page import="org.apache.commons.lang.RandomStringUtils" %>
<%@ page import="com.swdouglass.joid.AuthenticationRequest" %>
<%@ page import="com.swdouglass.joid.server.UserManager" %>
<%@ page import="com.swdouglass.joid.server.OpenIdServlet" %>
<%@ page import="com.swdouglass.joid.server.ReCaptcha" %>
<%@ page import="com.swdouglass.joid.server.User" %>
<%@ page import="com.swdouglass.joid.util.CookieUtils" %>
<%@ page import="com.swdouglass.joid.util.UrlUtils" %>
<%@ page import="java.net.URLDecoder" %>
<%!
  private UserManager userManager() {
    return OpenIdServlet.getUserManager();
  }

  private String getParam(HttpServletRequest request, String s) {
    String ret = (String) request.getAttribute(s);
    if (ret == null) {
      ret = request.getParameter(s);
    }
    // then try session
    if (ret == null) {
      HttpSession session = request.getSession(true);
      ret = (String) session.getAttribute(s);
    }
    return ret;
  }

  private boolean authenticate(HttpServletRequest request, String username, String password, String newuser) {
    User user = userManager().getUser(username);
    if (user == null) {
      if (newuser != null) { // means create new user check box is checked
        String captcha = ReCaptcha.check(getParam(request, OpenIdServlet.INIT_CAPTCHA_PRIVATE_KEY),
                request.getRemoteAddr(), request.getParameter(ReCaptcha.PARAM_RECAPTCHA_CHALLENGE),
                request.getParameter(ReCaptcha.PARAM_RECAPTCHA_RESPONSE));
        if (captcha == null) {
          user = new User(username, password);
          userManager().save(user);
          System.out.println("created new user: " + username);
        } else {
         // TODO: set the recaptcha error message so the javascript can pick it up?
          request.setAttribute(ReCaptcha.PARAM_RECAPTCHA_ERROR, captcha);
          return false;
        }
      } else {
        return false;
      }
    }
    if (userManager().login(user.getUsername(), password)) {
      request.getSession(true).setAttribute(OpenIdServlet.USERNAME_ATTRIBUTE, user.getUsername());
      request.getSession(true).setAttribute("user", user);
      return true;
    }
    return false;
  }
%>
<%
    String errorMsg = null;
// check if user is logging in.
    String username = request.getParameter("username");
    if (username != null) {
      if (authenticate(request, username, request.getParameter("password"), request.getParameter("newuser"))) {
        // ensure this user owns the claimed identity
        String claimedId = (String) session.getAttribute(AuthenticationRequest.OPENID_CLAIMED_ID);
        if (claimedId != null) {
          User user = (User) session.getAttribute("user");

          if (userManager().canClaim(user, claimedId)) {
            OpenIdServlet.idClaimed(session, claimedId);
            String query = request.getParameter("query");
            // then we'll redirect to login servlet again to finish up
            String baseUrl = UrlUtils.getBaseUrl(request);
            String openIdServer = baseUrl + "/login";
            response.sendRedirect(openIdServer + "?" + URLDecoder.decode(query, "utf-8"));
            return;
          } else {
            errorMsg = "You do not own the claimed identity.";
          }
        }
        if (request.getParameter("rememberMe") != null) {
          // store username and secret key combo for later retrieval and set cookies
          String secretKey = RandomStringUtils.randomAlphanumeric(128);
          CookieUtils.setCookie(response, OpenIdServlet.COOKIE_USERNAME, username);
          CookieUtils.setCookie(response, OpenIdServlet.COOKIE_AUTH_NAME, secretKey);
          userManager().remember(username, secretKey);
        }
      } else {
        // error for user side
        errorMsg = "Invalid login.";
      }
    } else {
        String openId = (String) session.getAttribute(AuthenticationRequest.OPENID_CLAIMED_ID);
        username = openId.substring(openId.lastIndexOf("/") + 1);
    }
%>
<html>
  <head>
    <style type="text/css">
      .error {
        font-weight: bold;
        color: red;
      }
    </style>
    <script type="text/javascript">
      /* see: http://www.quirksmode.org/ */
      var DHTML = (document.getElementById || document.all || document.layers);

      function getObj(name) {
        if (document.getElementById) {
          this.obj = document.getElementById(name);
          this.style = document.getElementById(name).style;
        } else if (document.all) {
          this.obj = document.all[name];
          this.style = document.all[name].style;
        } else if (document.layers) {
          this.obj = document.layers[name];
          this.style = document.layers[name];
        }
      }
      
      function toggleVisibility(id) {
        if (!DHTML) return;
        var x = new getObj(id);
        if ( x.style.visibility != "visible" ) {
          x.style.visibility="visible";
          x.style.height="auto";
        } else {
          x.style.visibility="hidden";
          x.style.height="0";
        }
      }
    </script>
  </head>
  <body>
    <img src="images/openid-logo-small.png">
    <%
    if (errorMsg != null) {
    %>
    <div class="error"><%=errorMsg%>
    </div>
    <%
    }
    %>
    <form action="login.jsp" method="post">
      <input type="hidden" name="query" value="<%=getParam(request, "query")%>"/>
      <input type="hidden" name="openid.realm"
             value="<%=getParam(request, "openid.realm")%>"/>

      <p>
        Allow access to realm: <a href="<%=getParam(request, "openid.realm")%>"
                            target="_blank"><%=getParam(request, "openid.realm")%></a>?
      </p>
      <table border="0">
        <tr>
          <td>Username:</td>
          <td><input type="text" name="username" value="<%=username%>"/></td>
        </tr>
        <tr>
          <td>Password:</td>
          <td><input type="password" name="password"/></td>
        </tr>
        <tr>
          <td>Create New User?</td>
          <td><input type="checkbox" name="newuser" onchange="toggleVisibility('joid_recaptcha');"/></td>
        </tr>
        <tr>
          <td colspan="2">
            <div id="joid_recaptcha" style="visibility: hidden;height: 0;">
              <%-- See recaptcha --%>
              <script type="text/javascript"
                      src="http://api.recaptcha.net/challenge?k=6LcdIQUAAAAAANP7sPbjnIq-ts_NMyJgs8GaLf-6">
              </script>
              <noscript>
                <iframe src="http://api.recaptcha.net/noscript?k=6LcdIQUAAAAAANP7sPbjnIq-ts_NMyJgs8GaLf-6"
                        height="300" width="500" frameborder="0"></iframe><br />
                <textarea name="recaptcha_challenge_field" rows="3" cols="40">
                </textarea>
                <input type="hidden" name="recaptcha_response_field"
                       value="manual_challenge" />
              </noscript>
            </div>
          </td>
        </tr>
        <tr>
          <td>Remember Me?</td>
          <td><input type="checkbox" name="rememberMe"/></td>
        </tr>
        <tr>
          <td>&nbsp;</td>
          <td><input type="submit" value="Submit"/></td>
        </tr>
      </table>
    </form>
    <p>
      <% if (session.getAttribute("user") != null) {%>
      Logged in as: <%=session.getAttribute("user")%>
      <% }%>
    </p>

  </body>
</html>
