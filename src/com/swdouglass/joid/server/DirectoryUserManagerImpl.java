/*
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
 */
package com.swdouglass.joid.server;

import com.swdouglass.joid.util.DirectoryUtil;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Implements a persistent {@link UserManager} using LDAP via JNDI.
 * 
 * @author scott
 */
public class DirectoryUserManagerImpl extends MemoryUserManagerImpl implements
  UserManager {

  private static final Log log = LogFactory.getLog(
    DirectoryUserManagerImpl.class);
  private InitialDirContext initialCtx;
  private static final String PASSWORD_ATTRIBUTE_PROP = "joid.directory.attribute.password";
  private static final String PASSWORD_ATTRIBUTE_PROP_DEFAULT = "userPassword";
  private static final String OPENID_OBJECTCLASS_PROP = "joid.directory.objectClass.openid";
  private static final String OPENID_OBJECTCLASS_PROP_DEFAULT = "labeledURI";

  public DirectoryUserManagerImpl() {
    try {
      initialCtx = DirectoryUtil.getInitialDirContext();
    } catch (NamingException ex) {
      log.warn("Could not create initial diretory context! " + ex);
      ex.printStackTrace();
    }
  }

  @Override
  public User getUser(String username) {
    User user = null;
    try {
      Attributes attrs = findAttributes(username, initialCtx);
      if (attrs != null) {
        if (log.isDebugEnabled()) {
          NamingEnumeration ne = attrs.getAll();
          while (ne.hasMore()) {
            log.debug(ne.next());
          }
        }
        // create the user, password very likely to be in binary form...
        user = new User(username, DirectoryUtil.getAttributeValue(attrs,
          PASSWORD_ATTRIBUTE_PROP, PASSWORD_ATTRIBUTE_PROP_DEFAULT));

        // set the list of OpenIDs
        Attribute openIDattr = attrs.get(DirectoryUtil.getProperty(
          OPENID_OBJECTCLASS_PROP,OPENID_OBJECTCLASS_PROP_DEFAULT));
        Enumeration e = openIDattr.getAll();
        Set<String> openIDs = new HashSet<String>();
        while (e.hasMoreElements()) {
          openIDs.add((String) e.nextElement());
        }
        user.setOpenIDs(openIDs);
      }
    } catch (NamingException ex) {
      log.warn("Error in finding the userame=" + username, ex);
    }
    return user;
  }

  private Attributes findAttributes(String inUsername,
    InitialDirContext ctx) throws NamingException {

    SearchControls ctls = new SearchControls();
    ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);

    // perform the search
    NamingEnumeration results = ctx.search("", "(uid={0})",
      new Object[]{inUsername}, ctls);

    Attributes outAttrs = null;
    if (results.hasMore()) {
      log.info("Found username \"" + inUsername + "\" in directory");
      outAttrs = ((SearchResult) results.next()).getAttributes();
    } else {
      log.info("Could NOT find username \"" + inUsername + "\" in directory");
    }
    return outAttrs;
  }

  @Override
  public void save(User user) {
    throw new UnsupportedOperationException("Not supported yet.");
  }

  @Override
  public boolean login(String inUsername, String inPassword) {
    return DirectoryUtil.login(inUsername, inPassword);
  }

  @Override
  public boolean canClaim(User user, String claimedId) {
    boolean result = false;
    if (user.getOpenIDs().contains(claimedId)) {
      result = true;
    }
    return result;
  }
}
