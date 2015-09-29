<%--
This page is a sample for consumers to use, but also serves as a testing page for running the server.
--%>
<%@ page import="com.swdouglass.joid.consumer.OpenIdFilter" %>
<%@ page import="com.swdouglass.joid.util.UrlUtils" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%
    String returnTo = UrlUtils.getBaseUrl(request);
    if (request.getParameter("signin") != null) {
      try {
        //FIXME: this example does not perform full normalization as per
        // OpenID 2.0: 7.2
        String id = request.getParameter("openid_identifier");
        if (!id.startsWith("http")) {
          id = "http://" + id;
        }
        if (id.lastIndexOf("/") < 7) {
          id = id + "/";
        }
        String trustRoot = returnTo;
        String s = OpenIdFilter.joid().getAuthUrl(id, returnTo, trustRoot);
        response.sendRedirect(s);
      } catch (Throwable e) {
        e.printStackTrace();
%>
An error occurred! Please press back and try again.
<%
      }
      return;
    }
%>
<html>
  <head><title>A Page I Want to Login To</title></head>
  <style type="text/css">
    body {
      font-family: sans-serif;
      font-size:76%;
    }
    strong {
      color:#505050;
    }
  </style>
  <body>
    <img src="images/openid-logo-small.png">
    <%--  style="background-color:gray; color:white; padding: 0;padding-top:1px; padding-left:5px; width:520px" --%>
    <%
    String loggedInAs = OpenIdFilter.getCurrentUser(session);
    if (loggedInAs != null) {
    %>
    <form action="logout.jsp">

      <table style="border: 1px dotted silver;"><tr><td style="width:420px;">
          <strong>You are logged in as:<br/> <%=loggedInAs%></strong></td><td style="width:100px;">
      <input type="submit" value="Logout" style="width:100px;"/></td></tr></table>

    </form>

    <%
    }
    %>
    <script type="text/javascript">
      function submitForm(url){
        document.getElementById("openid_identifier").value = url;
        document.getElementById("openid_form").submit();
      }
    </script>
    <form action="index.jsp" method="post" id="openid_form">
      <input type="hidden" name="signin" value="true"/>
      <table><tr><td style="width:420px;">
            <strong>Login with your <a href="http://openid.net/">OpenID</a> URL:</strong><br/>
            <%-- OpenID 2.0: 7.1 "The form field's name SHOULD be "openid_identifier" --%>
            <input type="text" size="40" value="<%=returnTo + "/user/austinpowers"%>"
                   name="openid_identifier" id="openid_identifier"
                   style="background: #FFFFFF url('images/login-bg.gif') no-repeat scroll 0pt 50%;
                   padding-left: 18px;"/><br/>
          <span style="font-size: 9pt;">For example: <tt>someone.bloghost.com</tt></span></td>
      <td style="width:100px;"><input type="submit" value="Login" style="width:100px;"/></td></tr></table>
    </form>
    <table style="width:520px">
      <tr valign="top"><td style="border-right: 1px dotted silver;">
          <strong>Login Via</strong><br/>
          <img src="http://l.yimg.com/us.yimg.com/i/ydn/openid-signin-yellow.png" alt="Sign in with Yahoo"
               onclick="submitForm('http://www.yahoo.com');"/><br/>
          <img src="http://buttons.googlesyndication.com/fusion/add.gif" alt="Sign in with Google"
               onclick="submitForm('https://www.google.com/accounts/o8/id');"/>
        </td>
        <td style="border-right: 1px dotted silver;">
          <strong>Get an OpenID</strong><br/>
          <a href="https://pip.verisignlabs.com/" target="_blank">Verisign</a><br/>
          <a href="http://www.myopenid.com/" target="_blank">myOpenID</a><br/>
          <a href="https://myvidoop.com/" target="_blank">myVidoop</a><br/>
          <a href="https://geneticmail.com/" target="_blank">GeneticMail</a><br/>
        </td>
        <td>
          <strong>About OpenID</strong><br/>
          <a href="http://openid.net/developers/specs" target="_blank">Specifications</a><br/>
          <a href="http://joid.googlecode.com/" target="_blank">JOID (Java OpenID)</a><br/>
          <a href="http://swdouglass.com/wiki/Wiki.jsp?page=JOID" target="_blank">JOID SWD (fork of JOID)</a><br/>
        </td>
      </tr>
    </table>
  </body>
</html>