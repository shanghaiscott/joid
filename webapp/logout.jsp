<%@ page import="com.swdouglass.joid.consumer.OpenIdFilter"%><%
    OpenIdFilter.logout(session);
    session.removeAttribute("user");
    session.invalidate();
    response.sendRedirect(request.getContextPath() + "/index.jsp");
%>