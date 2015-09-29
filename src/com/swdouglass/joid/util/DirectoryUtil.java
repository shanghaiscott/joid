/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.swdouglass.joid.util;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Properties;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.InitialDirContext;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 *
 * @author scott
 */
public class DirectoryUtil {

  private static Log log = LogFactory.getLog(DirectoryUtil.class);
  private static final String LDAP_PROPERTIES = "directory.properties";
  private static final String JNDI_PRINCIPAL = "java.naming.security.principal";
  private static final String JNDI_CREDENTIALS = "java.naming.security.credentials";
  private static final String OU_PEOPLE_PROP = "joid.directory.ou.people";
  private static final String OU_PEOPLE_PROP_DEFAULT = "People";
  private static final String DN_ROOT_PROP = "joid.directory.root";
  private static final String USER_ATTRIBUTE_PROP = "joid.directory.attribute.user";
  private static final String USER_ATTRIBUTE_PROP_DEFAULT = "uid";
  public static Properties prop;


  static {
    prop = new Properties();
    try {
      prop.load(Thread.currentThread().getContextClassLoader().
        getResourceAsStream(LDAP_PROPERTIES));
    } catch (IOException ex) {
      log.warn("Failed to load directory properties!");
    }
  }

  public static InitialDirContext getInitialDirContext() throws NamingException {
    return new InitialDirContext(prop);
  }

  public static String getProperty(String inPropertyName, String inDefaultValue) {
    return prop.getProperty(inPropertyName, inDefaultValue);
  }

  public static Boolean login(String inUsername, String inPasword) {
    boolean auth = false;
    Properties uProp = cloneProperties(prop);
    uProp.setProperty(JNDI_PRINCIPAL, makeDn(inUsername));
    uProp.setProperty(JNDI_CREDENTIALS, inPasword);
    if (log.isDebugEnabled()) {
      Enumeration e = uProp.elements();
      while (e.hasMoreElements()) {
        log.debug(e.nextElement());
      }
    }
    try {
      InitialDirContext idc = new InitialDirContext(uProp);
      auth = true;
      idc.close();
      uProp = null;
    } catch (NamingException e) {
      log.info("Bind failed: " + e);
    }

    return auth;
  }

  public static Properties cloneProperties(Properties inProperties) {
    Properties nProp = new Properties();
    Enumeration names = inProperties.propertyNames();
    while (names.hasMoreElements()) {
      String propName = (String) names.nextElement();
      nProp.setProperty(
        propName,
        inProperties.getProperty(propName));
    }
    return nProp;
  }

  public static String makeDn(String inUsername) {
    StringBuilder sb = new StringBuilder();
    sb.append(prop.getProperty(USER_ATTRIBUTE_PROP, USER_ATTRIBUTE_PROP_DEFAULT));
    sb.append("=");
    sb.append(inUsername);
    sb.append(",");
    sb.append("ou=");
    sb.append(prop.getProperty(OU_PEOPLE_PROP, OU_PEOPLE_PROP_DEFAULT));
    sb.append(",");
    sb.append(prop.getProperty(DN_ROOT_PROP));
    return sb.toString();
  }

  public static String getAttributeValue(Attributes attrs, String inName,
    String inDefaultName) throws NamingException {
    String result = "";
    Object value = attrs.get(getProperty(
      inName, inDefaultName)).get();
    if (value instanceof byte[]) {
      result = new String((byte[]) value);
    } else if (value instanceof String) {
      result = (String) value;
    }
    return result;
  }
}
