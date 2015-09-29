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
/*
 * This meterial is licensed to you under the Apache License, 
 * Version 2.0 (the "License"); you may not use this file 
 * except in compliance with the License.  You may obtain
 * a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.swdouglass.joid.store;

import javax.naming.NameAlreadyBoundException;
import javax.naming.NameNotFoundException;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import com.swdouglass.joid.Association;
import com.swdouglass.joid.Nonce;
import com.swdouglass.joid.OpenIdException;
import com.swdouglass.joid.Store;
import com.swdouglass.joid.util.DirectoryUtil;

public class DirectoryStoreImpl extends Store {

  private static final Log log = LogFactory.getLog(DirectoryStoreImpl.class);
  private static final String OU_OPENID_PROP = "joid.directory.ou.openid";
  private static final String OU_OPENID_PROP_DEFAULT = "openid";
  private static final String OU_ASSOCIATION_PROP = "joid.directory.ou.association";
  private static final String OU_ASSOCIATION_PROP_DEFAULT = "association";
  private static final String OU_NONCE_PROP = "joid.directory.ou.nonce";
  private static final String OU_NONCE_PROP_DEFAULT = "nonce";
  private static final String OU = "ou=";
  private static final String CN = "cn=";
  private InitialDirContext initialCtx;
  private String ouOpenID;
  private String ouAssociation;
  private String ouNonce;

  public DirectoryStoreImpl() {
    try {
      // Set up environment for creating the initial context
      initialCtx = DirectoryUtil.getInitialDirContext();

      this.setOuOpenID(OU.concat(DirectoryUtil.getProperty(OU_OPENID_PROP,
        OU_OPENID_PROP_DEFAULT)));
      this.setOuAssociation(OU.concat(DirectoryUtil.getProperty(
        OU_ASSOCIATION_PROP, OU_ASSOCIATION_PROP_DEFAULT)));
      this.setOuNonce(OU.concat(DirectoryUtil.getProperty(OU_NONCE_PROP,
        OU_NONCE_PROP_DEFAULT)));

      //try to create parent contexes
      Attributes attrs = new BasicAttributes(true); // case-ignore
      Attribute objclass = new BasicAttribute("objectclass");
      objclass.add("top");
      objclass.add("organizationalUnit");
      attrs.put(objclass);
      DirContext baseCtx = initialCtx.createSubcontext(ouOpenID, attrs);
      baseCtx.createSubcontext(ouAssociation, attrs);
      baseCtx.createSubcontext(ouNonce, attrs);

    } catch (NameAlreadyBoundException ex) {
      //ignore
    } catch (Exception ex) {
      log.warn(ex);
      ex.printStackTrace();
    }
  }

  @Override
  public void deleteAssociation(Association a) throws OpenIdException {
    try {
      initialCtx.unbind(getAssociationName(a.getHandle()));
    } catch (NamingException ex) {
      throw new OpenIdException("Error in deleting the association=" + a.
        getHandle(), ex);
    }
  }

  @Override
  public Association findAssociation(String handle) throws OpenIdException {
    Association result = null;
    try {
      result = (Association) initialCtx.lookup(getAssociationName(handle));
    } catch (NameNotFoundException ex) {
      //
    } catch (NamingException ex) {
      throw new OpenIdException("Error in finding the association=" + handle, ex);
    }
    return result;
  }

  @Override
  public Nonce findNonce(String nonce) throws OpenIdException {
    Nonce result = null;
    try {
      result = (Nonce) initialCtx.lookup(getNonceName(nonce));
    } catch (NameNotFoundException ex) {
      //
    } catch (NamingException ex) {
      throw new OpenIdException("Error in finding the nonce=" + nonce, ex);
    }
    return result;
  }

  @Override
  public void saveAssociation(Association a) throws OpenIdException {
    try {
      initialCtx.bind(getAssociationName(a.getHandle()), a);
    } catch (NamingException ex) {
      throw new OpenIdException("Error in storing the association=" + a.
        getHandle(), ex);
    }
  }

  @Override
  public void saveNonce(Nonce n) throws OpenIdException {
    try {
      initialCtx.bind(getNonceName(n.getNonce()), n);
    } catch (NamingException ex) {
      throw new OpenIdException("Error in storing the nonce=" + n.getNonce(), ex);
    }
  }

  private String getAssociationName(String assoc) {
    StringBuilder sb = new StringBuilder();
    sb.append(CN);
    sb.append(assoc);
    sb.append(",");
    sb.append(getOuAssociation());
    sb.append(",");
    sb.append(getOuOpenID());
    debug(sb.toString());
    return sb.toString();
  }

  private String getNonceName(String nonce) {
    StringBuilder sb = new StringBuilder();
    sb.append(CN);
    sb.append(nonce);
    sb.append(",");
    sb.append(getOuNonce());
    sb.append(",");
    sb.append(getOuOpenID());
    debug(sb.toString());
    return sb.toString();
  }

  /**
   * @return the ouOpenID
   */
  public String getOuOpenID() {
    return ouOpenID;
  }

  /**
   * @param ouOpenID the ouOpenID to set
   */
  public void setOuOpenID(String ouOpenID) {
    this.ouOpenID = ouOpenID;
  }

  /**
   * @return the ouAssociation
   */
  public String getOuAssociation() {
    return ouAssociation;
  }

  /**
   * @param ouAssociation the ouAssociation to set
   */
  public void setOuAssociation(String ouAssociation) {
    this.ouAssociation = ouAssociation;
  }

  /**
   * @return the ouNonce
   */
  public String getOuNonce() {
    return ouNonce;
  }

  /**
   * @param ouNonce the ouNonce to set
   */
  public void setOuNonce(String ouNonce) {
    this.ouNonce = ouNonce;
  }

  private void debug(String message) {
    if (log.isDebugEnabled()) {
      log.debug(message);
    }
  }
}
