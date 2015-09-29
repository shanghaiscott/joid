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

//
// (C) Copyright 2007 VeriSign, Inc.  All Rights Reserved.
//
// VeriSign, Inc. shall have no responsibility, financial or
// otherwise, for any consequences arising out of the use of
// this material. The program material is provided on an "AS IS"
// BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied.
//
// Distributed under an Apache License
// http://www.apache.org/licenses/LICENSE-2.0
//
package com.swdouglass.joid;

import com.swdouglass.joid.extension.SimpleRegistration;
import com.swdouglass.joid.extension.Extension;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.logging.Log;

/**
 * Represents an OpenID authentication request.
 */
public class AuthenticationRequest extends Request {

  private final static Log log = LogFactory.getLog(AuthenticationRequest.class);
  private Map<String,String> extendedMap;
  private String claimed_id;
  private String identity;
  private String handle;
  private String returnTo;
  private String trustRoot;
  private SimpleRegistration sreg;
  public final static String OPENID_CLAIMED_ID = "openid.claimed_id";
  public final static String OPENID_IDENTITY = "openid.identity";
  public final static String OPENID_ASSOC_HANDLE = "openid.assoc_handle";
  public final static String ID_SELECT = "http://specs.openid.net/auth/2.0/identifier_select";
  public final static String CHECKID_IMMEDIATE = "checkid_immediate";
  public final static String CHECKID_SETUP = "checkid_setup";
  public final static String OPENID_RETURN_TO = "openid.return_to";
  //trust_root is the 1.x equivalent to trust_realm in 2.x
  public final static String OPENID_TRUST_ROOT = "openid.trust_root";
  public final static String OPENID_REALM = "openid.realm";
  public static String OPENID_DH_CONSUMER_PUBLIC = "openid.dh_consumer_public";
  public static String OPENID_SESSION_TYPE = "openid.session_type";
  public final static String DH_SHA1 = "DH-SHA1";
  private static Map<String,String> statelessMap = new HashMap<String,String>();
  private static AssociationRequest statelessAr;

  static {
    statelessMap.put(AuthenticationRequest.OPENID_SESSION_TYPE,
      AuthenticationRequest.DH_SHA1);
    // this value is not used for stateless, but it's not a valid
    // association request unless it's there
    statelessMap.put(AuthenticationRequest.OPENID_DH_CONSUMER_PUBLIC,
      Crypto.convertToString(BigInteger.valueOf(1)));
    try {
      // the request mode is irrelevant
      statelessAr = new AssociationRequest(statelessMap, "");
    } catch (OpenIdException e) {
      // should not happen
      throw new RuntimeException(e);
    }
  }

  /**
   * Creates a standard authentication request.
   *
   * @param identity    the openid identity.
   * @param returnTo    the return_to value.
   * @param trustRoot   the openid trust_root.
   * @param assocHandle the openid association handle.
   * @return an AuthenticationRequest.
   * @throws OpenIdException if the request cannot be created.
   */
  public static AuthenticationRequest create(String identity, String returnTo,
    String trustRoot, String assocHandle)
    throws OpenIdException {
    Map<String,String> map = new HashMap<String,String>();
    map.put("openid.mode", CHECKID_SETUP);
    map.put(OPENID_IDENTITY, identity);
    map.put(OPENID_CLAIMED_ID, identity);
    // these three are apparently all the same (see index.jsp)
    map.put(OPENID_RETURN_TO, returnTo);
    // if we don't get here via our index.jsp, but from another relay,
    // the realm will be null as it was only being set in index.jsp.
    //map.put(OPENID_TRUST_ROOT, trustRoot);
    //map.put(OPENID_REALM, trustRoot);
    map.put(OPENID_TRUST_ROOT, trustRoot);
    map.put(OPENID_REALM, returnTo);
    map.put(OPENID_NS, OPENID_20_NAMESPACE);
    map.put(OPENID_ASSOC_HANDLE, assocHandle);
    return new AuthenticationRequest(map, CHECKID_SETUP);
  }

  AuthenticationRequest(Map<String,String> map, String mode) throws OpenIdException {
    super(map, mode);
    extendedMap = new HashMap<String,String>();
    for (Map.Entry mapEntry : map.entrySet()) {
      String key = (String) mapEntry.getKey();
      String value = (String) mapEntry.getValue();

      if (OPENID_NS.equals(key)) {
        this.ns = value;
      } else if (OPENID_IDENTITY.equals(key)) {
        this.identity = value;
      } else if (OPENID_CLAIMED_ID.equals(key)) {
        this.claimed_id = value;
      } else if (OPENID_ASSOC_HANDLE.equals(key)) {
        this.handle = value;
      } else if (OPENID_RETURN_TO.equals(key)) {
        this.returnTo = value;
      } else if (OPENID_TRUST_ROOT.equals(key) || OPENID_REALM.equals(key)) {
        this.trustRoot = value;
      } else if (key != null && key.startsWith("openid.")) {
        String foo = key.substring(7);  // remove "openid."
        if ((!(OPENID_RESERVED_WORDS.contains(foo))) && (!foo.startsWith("sreg."))) {
          extendedMap.put(foo, value);
        }
      }
    }
    this.sreg = new SimpleRegistration(map);
    checkInvariants();
  }

  @Override
  public Map<String,String> toMap() {
    Map<String,String> map = super.toMap();

    if (claimed_id != null) {
      map.put(AuthenticationRequest.OPENID_CLAIMED_ID, claimed_id);
    }
    map.put(AuthenticationRequest.OPENID_IDENTITY, identity);
    map.put(AuthenticationRequest.OPENID_ASSOC_HANDLE, handle);
    map.put(AuthenticationRequest.OPENID_RETURN_TO, returnTo);
    map.put(AuthenticationRequest.OPENID_TRUST_ROOT, trustRoot);
    map.put(AuthenticationRequest.OPENID_REALM, trustRoot);

    if (extendedMap != null && !extendedMap.isEmpty()) {
      for (Map.Entry mapEntry : extendedMap.entrySet()) {
        String key = (String) mapEntry.getKey();
        String value = (String) mapEntry.getValue();
        if (value == null) {
          continue;
        }
        // all keys start "openid." in the set
        map.put("openid." + key, value);
      }
    }

    return map;
  }

  /**
   * Returns whether this request is immediate, that is, whether the
   * authentication mode is "CHECKID_IMMEDIATE".
   *
   * @return true if this request is immediate; false otherwise.
   */
  public boolean isImmediate() {
    return AuthenticationRequest.CHECKID_IMMEDIATE.equals(this.mode);
  }

  private void checkInvariants() throws OpenIdException {
    if (mode == null) {
      throw new OpenIdException("Missing mode");
    }
    if (identity == null) {
      throw new OpenIdException("Missing identity");
    }
    // This seems to be bogus, as both the 1.1. and 2.0 spec
    // state that the claimed identifier is the same as the identity
    //if (claimed_id != null && !this.isVersion2()) {
    //  throw new OpenIdException("claimed_id not valid in version 1.x");
    //}
    if (trustRoot == null) {
      if (returnTo != null) {
        trustRoot = returnTo;
      } else {
        throw new OpenIdException("Missing trust root");
      }
    }

    checkTrustRoot();

    Set<String> namespaces = new HashSet<String>();
    Set<String> entries = new HashSet<String>();
    for (Map.Entry mapEntry : extendedMap.entrySet()) {
      String key = (String) mapEntry.getKey();
      // all keys start "openid." in the set

      if (key.startsWith("ns.")) {
        key = key.substring(3);
        if (OPENID_RESERVED_WORDS.contains(key)) {
          throw new OpenIdException("Cannot redefine: " + key);
        }
        if (namespaces.contains(key)) {
          throw new OpenIdException("Multiple definitions: " + key);
        }
        namespaces.add(key);
      } else {
        if (entries.contains(key)) {
          throw new OpenIdException("Multiple definitions: " + key);
        }
        entries.add(key);
      }
    }
    // don't check for invalid parameters on 1.x requests; just
    // silently ignore them
    if (this.isVersion2()) {
      for (String key : entries) {
        int period = key.indexOf('.');
        if (period != -1) {
          key = key.substring(0, period);
        }
        if (!namespaces.contains(key)) {
          throw new OpenIdException("No such namespace: " + key);
        }
      }
    }
  }

  private void checkTrustRoot() throws OpenIdException {
    if (trustRoot == null) {
      throw new OpenIdException("No " + OPENID_TRUST_ROOT + " given");
    }

    // URI fragments are not allowed in trustroot 
    if (trustRoot.indexOf('#') > 0) {
      throw new OpenIdException("URI fragments are not allowed");
    }

    // Matched if:
    // 1. trustroot and returnto are identical
    // 2. trustroot contains wild-card characters "*.", and the
    // trailing part of the returnto's domain is identical to the
    // part of the trustroot following the "*." wildcard
    //
    // Trust root           Return to
    // ----------           ---------
    // example.com      =>  example.com      ==> ok
    // *.example.com    =>  example.com      ==> ok
    // *.example.com    =>  a.example.com    ==> ok
    // www.example.com  =>  a.example.com    ==> not ok
    //
    URL r, t;
    try {
      r = new URL(returnTo);
      t = new URL(trustRoot);
    } catch (MalformedURLException e) {
      throw new OpenIdException("Malformed URL");
    }

    String tHost = new StringBuilder(t.getHost()).reverse().toString();
    String rHost = new StringBuilder(r.getHost()).reverse().toString();

    String[] tNames = tHost.split("\\.");
    String[] rNames = rHost.split("\\.");
    int len = (tNames.length > rNames.length) ? rNames.length : tNames.length;

    int i;
    for (i = 0; i < len; i += 1) {
      if (!(tNames[i].equals(rNames[i])) && (!tNames[i].equals("*"))) {
        throw new OpenIdException("returnTo not in trustroot set: " +
          tNames[i] + ", " + rNames[i]);
      }
    }
    if ((i < tNames.length) && (!tNames[i].equals("*"))) {
      throw new OpenIdException("returnTo not in trustroot set: " + tNames[1]);
    }

    // The return to path is equal to or a sub-directory of the
    // realm's (trustroot's) path.
    //
    // Trust root     Return to
    // ----------     ---------
    // /a/b/c     =>  /a/b/c/d    ==> ok
    // /a/b/c     =>  /a/b        ==> not ok
    // /a/b/c     =>  /a/b/b      ==> not ok
    //

    String tPath = t.getPath();
    String rPath = r.getPath();

    int n = rPath.indexOf(tPath);
    if (n != 0) {
      throw new OpenIdException("return to & trust root paths mismatch");
    }

  // if we're here, we're good to go!
  }

  @Override
  public Response processUsing(ServerInfo si) throws OpenIdException {
    Store store = si.getStore();
    Crypto crypto = si.getCrypto();
    Association assoc = null;
    String invalidate = null;
    if (handle != null) {
      assoc = store.findAssociation(handle);
      if (assoc != null && assoc.hasExpired()) {
        log.info("Association handle has expired: " + handle);
        assoc = null;
      }
    }
    if (handle == null || assoc == null) {
      log.info("Invalidating association handle: " + handle);
      invalidate = handle;
      assoc = store.generateAssociation(statelessAr, crypto);
      store.saveAssociation(assoc);
    }
    return new AuthenticationResponse(si, this, assoc, crypto, invalidate);
  }

  /**
   * Returns the identity used in this authentication request.
   *
   * @return the identity.
   */
  public String getIdentity() {
    return identity;
  }

  /**
   * Returns the extensions in this authentication request.
   *
   * @return the extensions; empty if none.
   */
  public Map<String,String> getExtensions() {
    return extendedMap;
  }

  /**
   * Add the extension map to the internal extensions map.
   *
   * @param map Map<String, String> of name value pairs
   */
  public void addExtensions(Map<String,String> map) {
    for (Map.Entry mapEntry : map.entrySet()) {
      String key = (String) mapEntry.getKey();
      String value = (String) mapEntry.getValue();
      extendedMap.put(key, value);
    }
  }

  /**
   * Add extension object's parameters to the extensions map.
   */
  public void addExtension(Extension ext) {
    addExtensions(ext.getParamMap());
  }

  /**
   * Returns whether the given identity equals {@link #ID_SELECT}.
   *
   * @return true if the identity equals {@link #ID_SELECT}.
   */
  public boolean isIdentifierSelect() {
    return AuthenticationRequest.ID_SELECT.equals(identity);
  }

  /**
   * Returns the claimed identity used in this authentication request.
   *
   * @return the claimed identity.
   */
  public String getClaimedIdentity() {
    return claimed_id;
  }

  /**
   * Sets the identity used in this authentication request.
   *
   * @param identity the identity.
   */
  public void setIdentity(String identity) {
    this.identity = identity;
  }

  /**
   * Returns the 'return to' address in this authentication request.
   *
   * @return the address.
   */
  public String getReturnTo() {
    return returnTo;
  }

  /**
   * Returns the handle used in this authentication request.
   *
   * @return the handle
   */
  public String getHandle() {
    return handle;
  }

  /**
   * Returns the trust root address in this authentication request.
   *
   * @return the address.
   */
  public String getTrustRoot() {
    return trustRoot;
  }

  /**
   * Returns the simple registration fields in this authentication request.
   *
   * @return the sreg fields; or null if none present.
   */
  public SimpleRegistration getSimpleRegistration() {
    return sreg;
  }

  /**
   * Sets the simple registration fields in this authentication request.
   *
   * @param sreg the registration fields.
   */
  public void setSimpleRegistration(SimpleRegistration sreg) {
    this.sreg = sreg;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("[AuthenticationRequest ");
    s.append(super.toString());
    s.append(", sreg=");
    s.append(sreg);
    s.append(", claimed identity=");
    s.append(claimed_id);
    s.append(", identity=");
    s.append(identity);
    s.append(", handle=");
    s.append(handle);
    s.append(", return to=");
    s.append(returnTo);
    s.append(", trust root=");
    s.append(trustRoot);
    s.append("]");
    return s.toString() ;
  }
}
