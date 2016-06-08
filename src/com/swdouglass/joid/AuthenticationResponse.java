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
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.logging.Log;

/**
 * Represents an OpenID authentication response.
 */
public class AuthenticationResponse extends Response {

  private static Log log = LogFactory.getLog(AuthenticationResponse.class);
  public static String OPENID_PREFIX = "openid.";
  public static String OPENID_RETURN_TO = "openid.return_to";
  public static String OPENID_OP_ENDPOINT = "openid.op_endpoint";
  public static String OPENID_IDENTITY = "openid.identity";
  //public static String OPENID_ERROR = "openid.error";
  public static String OPENID_NONCE = "openid.response_nonce";
  public static String OPENID_INVALIDATE_HANDLE = "openid.invalidate_handle";
  public static String OPENID_ASSOCIATION_HANDLE = "openid.assoc_handle";
  public static String OPENID_SIGNED = "openid.signed";
  // package scope so that ResponseFactory can trigger on this key
  public static String OPENID_SIG = "openid.sig";
  private Map<String,String> extendedMap;
  private String claimed_id;
  private String identity;
  private String returnTo;
  private String nonce;
  private String invalidateHandle;
  private String associationHandle;
  private String signed;
  private String algo;
  private String signature;
  private SimpleRegistration sreg;
  private String urlEndPoint;
  private byte[] key;

  /**
   * Returns the signature in this response.
   * @return the signature in this response.
   */
  public String getSignature() {
    return signature;
  }

  /**
   * Returns the list of signed elements in this response.
   * @return the comma-separated list of signed elements in this response.
   */
  public String getSignedList() {
    return signed;
  }

  /**
   * Returns the association handle in this response.
   * @return the association handle in this response.
   */
  public String getAssociationHandle() {
    return associationHandle;
  }

  /**
   * Returns the internal elements mapped to a map. The keys used
   * are those defined by the specification, for example
   * <code>openid.mode</code>.
   *
   * TODO: Made public only for unit tests. Needs to package-scope
   * limit this method.
   *
   * @return a map with all internal values mapped to their specification
   * keys.
   */
  @Override
  public Map<String,String> toMap() {
    Map<String,String> map = super.toMap();

    if (isVersion2()) {
      map.put(AuthenticationResponse.OPENID_OP_ENDPOINT, urlEndPoint);
    }
    map.put(AuthenticationResponse.OPENID_MODE, mode);
    map.put(AuthenticationResponse.OPENID_IDENTITY, identity);
    map.put(AuthenticationResponse.OPENID_RETURN_TO, returnTo);
    map.put(AuthenticationResponse.OPENID_NONCE, nonce);
    if (claimed_id != null) {
      map.put(AuthenticationRequest.OPENID_CLAIMED_ID, claimed_id);
    }
    if (invalidateHandle != null) {
      map.put(AuthenticationResponse.OPENID_INVALIDATE_HANDLE, invalidateHandle);
    }
    map.put(AuthenticationResponse.OPENID_ASSOCIATION_HANDLE, associationHandle);
    if (signed != null) {
      map.put(AuthenticationResponse.OPENID_SIGNED, signed);
    }
    map.put(AuthenticationResponse.OPENID_SIG, signature);

    debug("sreg in authnresp = " + sreg);
    for (Map.Entry mapEntry: sreg.getSuppliedValues().entrySet()) {
      String _key = (String) mapEntry.getKey();
      String value = (String) mapEntry.getValue();
      map.put(SimpleRegistration.OPENID_SREG + "." + _key, value);
    }
    
    if (!sreg.getSuppliedValues().entrySet().isEmpty() && isVersion2()) {
      map.put(Message.OPENID_NS + ".sreg", sreg.getNamespace());
    }

    if (extendedMap != null && !extendedMap.isEmpty()) {
      for (Map.Entry mapEntry: extendedMap.entrySet()) {
        String _key = (String) mapEntry.getKey();
        String value = (String) mapEntry.getValue();
        map.put(OPENID_PREFIX + _key, value);
      }
    }

    return map;
  }

  private String generateNonce() {
    String crumb = Crypto.generateCrumb();
    //http://www.iso.org/iso/support/faqs/faqs_widely_used_standards/widely_used_standards_other/date_and_time_format.htm
    SimpleDateFormat dateTime = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
    return dateTime.format(new Date()) + crumb;
  }

  /**
   * Unrolls this response as a string. This string will use encoding
   * suitable for URLs. The string will use the same namespace as the
   * incoming request.
   *
   * @param req the original request.
   * @param e any exception that occurred while processing <code>req</code>,
   * may be null.
   *
   * @return the response as a string.
   */
  public static String toUrlStringResponse(Request req, OpenIdException e) {
    Map<String,String> map = new HashMap<String,String>();
    map.put(AuthenticationResponse.OPENID_MODE, "error");
    if (req != null) {
      if (req.isVersion2()) {
        map.put(AuthenticationResponse.OPENID_NS, req.getNamespace());
      }
      map.put(AuthenticationResponse.OPENID_ERROR, e.getMessage());
    } else {
      map.put(AuthenticationResponse.OPENID_ERROR,  "OpenID request error");
    }
    try {
      return new AuthenticationResponse(map).toUrlString();
    } catch (OpenIdException ex) {
      // this should never happen
      log.error(ex);
      return "internal error";
    }
  }

  /**
   * Only public for unit tests. Do not use.
   */
  public String sign(byte[] key, String signed)
    throws OpenIdException {
    return sign(this.algo, key, signed);
  }

  /**
   * Signs the elements designated by the signed list with the given key and
   * returns the result encoded to a string.
   *
   * @param algorithm the algorithm to use (HMAC-SHA1, HMAC-SHA256)
   * @param key the key to sign with (HMAC-SHA1, HMAC-SHA256)
   * @param signed the comma-separated list of elements to sign. The elements
   * must be mapped internally.
   * @return the Base 64 encoded result.
   * @throws OpenIdException at signature errors, or if the signed list
   * points to elements that are not mapped.
   */
  public String sign(String algorithm, byte[] key, String signed)
    throws OpenIdException {
    Map map = toMap();
    debug("in sign() map=" + map);
    debug("in sign() signed=" + signed);
    StringTokenizer st = new StringTokenizer(signed, ",");
    StringBuilder sb = new StringBuilder();
    while (st.hasMoreTokens()) {
      String s = st.nextToken();
      String name = "openid." + s;
      String value = (String) map.get(name);
      if (value == null) {
        throw new OpenIdException("Cannot sign non-existent mapping: " + s);
      }
      sb.append(s);
      sb.append(':');
      sb.append(value);
      sb.append('\n');
    }
    try {
      byte[] b;
      if (algorithm == null) {
        algorithm = AssociationRequest.HMAC_SHA1;
      }
      if (algorithm.equals(AssociationRequest.HMAC_SHA1)) {
        b = Crypto.hmacSha1(key, sb.toString().getBytes("UTF-8"));
      } else if (algorithm.equals(AssociationRequest.HMAC_SHA256)) {
        b = Crypto.hmacSha256(key, sb.toString().getBytes("UTF-8"));
      } else {
        throw new OpenIdException("Unknown signature algorithm");
      }
      return Crypto.convertToString(b);
    } catch (UnsupportedEncodingException e) {
      throw new OpenIdException(e);
    } catch (InvalidKeyException e) {
      throw new OpenIdException(e);
    } catch (NoSuchAlgorithmException e) {
      throw new OpenIdException(e);
    }
  }

  /**
   * throws at errors in signature creation
   */
  AuthenticationResponse(ServerInfo serverInfo, AuthenticationRequest ar,
    Association a, Crypto crypto, String invalidateHandle)
    throws OpenIdException {
    super(null);
    mode = "id_res";
    claimed_id = ar.getClaimedIdentity();
    identity = ar.getIdentity();
    returnTo = ar.getReturnTo();
    ns = ar.getNamespace();
    nonce = generateNonce();
    this.urlEndPoint = serverInfo.getUrlEndPoint();
    this.invalidateHandle = invalidateHandle; //may be null
    associationHandle = a.getHandle();
    signed = "assoc_handle,identity,response_nonce,return_to";
    if (claimed_id != null) {
      signed += ",claimed_id";
    }
    if (isVersion2()) {
      signed += ",op_endpoint";
    }
    sreg = ar.getSimpleRegistration();
    debug("sreg=" + sreg);
    if (sreg != null) {
      StringBuilder s = new StringBuilder(signed);
      debug("sreg supplied values=" + sreg.getSuppliedValues());
      for (Map.Entry mapEntry : sreg.getSuppliedValues().entrySet()) {
        String _key = (String) mapEntry.getKey();
        s.append(",sreg.");
        s.append(_key);
      }
      signed = s.toString();
    }
    key = a.getMacKey();
    this.algo = a.getAssociationType();
    signature = sign(key, signed);
    extendedMap = new HashMap<String,String>();
  }

  public AuthenticationResponse(Map<String,String> map) throws OpenIdException {
    super(map);
    extendedMap = new HashMap<String,String>();
    for (Map.Entry mapEntry : map.entrySet()) {
      String _key = (String) mapEntry.getKey();
      String value = (String) mapEntry.getValue();

      if (AuthenticationResponse.OPENID_MODE.equals(_key)) {
        mode = value;
      } else if (AuthenticationResponse.OPENID_IDENTITY.equals(_key)) {
        identity = value;
      } else if (AuthenticationRequest.OPENID_CLAIMED_ID.equals(_key)) {
        claimed_id = value;
      } else if (AuthenticationResponse.OPENID_RETURN_TO.equals(_key)) {
        returnTo = value;
      } else if (OPENID_NONCE.equals(_key)) {
        nonce = value;
      } else if (OPENID_INVALIDATE_HANDLE.equals(_key)) {
        invalidateHandle = value;
      } else if (OPENID_ASSOCIATION_HANDLE.equals(_key)) {
        associationHandle = value;
      } else if (OPENID_SIGNED.equals(_key)) {
        signed = value;
      } else if (OPENID_SIG.equals(_key)) {
        signature = value;
      } else if (OPENID_OP_ENDPOINT.equals(_key)) {
        urlEndPoint = value;
        // we get op_endpoint without a 2.0 ns for some
        // check_auth requests
        // since we use this class to recalculate the
        // signature we need to set version 2 explicitly or we
        // won't include the op_endpoint in the map
        // (op_endpoint isn't allowed in 1.x responses)
        if (ns == null) {
          ns = OPENID_20_NAMESPACE;
        }
      } else if (_key != null && _key.startsWith("openid.")) {
        String foo = _key.substring(7);  // remove "openid."
        if ((!(OPENID_RESERVED_WORDS.contains(foo))) && (!foo.startsWith("sreg."))) {
          extendedMap.put(foo, value);
        }
      }
    }
    this.sreg = SimpleRegistration.parseFromResponse(map);
    debug("authn resp constr sreg=" + sreg);
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
  public void addExtensions(Map<String,String> map) throws OpenIdException {
    StringBuilder sb = new StringBuilder(signed);
    for (Map.Entry mapEntry : map.entrySet()){
      String _key = (String) mapEntry.getKey();
      String value = (String) mapEntry.getValue();
      extendedMap.put(_key, value);
      // add items to signature
      // signed should already contain a list of base params to sign
      sb.append(",");
      sb.append(_key);
    }
    signed = sb.toString();
    // recalculate signature
    signature = sign(key, signed);
  }

  /**
   * Add extension object's parameters to the extensions map.
   */
  public void addExtension(Extension ext) throws OpenIdException {
    addExtensions(ext.getParamMap());
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("[AuthenticationResponse ");
    s.append(super.toString());
    if (sreg != null) {
      s.append(", sreg=");
      s.append(sreg);
    }
    s.append(", mode=");
    s.append(mode);
    s.append(", algo=");
    s.append(algo);
    s.append(", nonce=");
    s.append(nonce);
    s.append(", association handle=");
    s.append(associationHandle);
    s.append(", invalidation handle=");
    s.append(invalidateHandle);
    s.append(", signed=");
    s.append(signed);
    s.append(", signature=");
    s.append(signature);
    s.append(", identity=");
    s.append(identity);
    s.append(", return to=");
    s.append(returnTo);
    s.append("]");
    return s.toString();
  }

  public String getClaimedId() {
    return claimed_id;
  }

  public String getIdentity() {
    return identity;
  }

  public String getReturnTo() {
    return returnTo;
  }

  public String getNonce() {
    return nonce;
  }

  public String getInvalidateHandle() {
    return invalidateHandle;
  }

  public String getSigned() {
    return signed;
  }

  public String getAlgo() {
    return algo;
  }

  public SimpleRegistration getSreg() {
    return sreg;
  }

  public String getUrlEndPoint() {
    return urlEndPoint;
  }

  void debug(String message) {
    if (log.isDebugEnabled()) {
      log.debug(message);
    }
  }
}
