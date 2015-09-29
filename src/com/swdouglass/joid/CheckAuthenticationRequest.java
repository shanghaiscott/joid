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

import java.util.Map;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Represents an OpenID check authentication request.
 */
public class CheckAuthenticationRequest extends Request {

  public final static String OPENID_ASSOC_HANDLE = "openid.assoc_handle";
  private final static Log log = LogFactory.getLog(CheckAuthenticationRequest.class);
  private AuthenticationResponse ar;
  private String handle;

  /**
   * Creates a check_authentication request.
   *
   * TODO: Made public to be accessible from unit tests only. Need
   * to rework that to change access level during test time.
   *
   * @param map the map of incoming openid parameters
   * @param mode always "check_authentication"
   */
  public CheckAuthenticationRequest(Map<String,String> map, String mode)
  throws OpenIdException {
    super(map, mode);
    ar = new AuthenticationResponse(map);
    handle = ar.getAssociationHandle();
    checkInvariants();
  }

  private void checkInvariants() throws OpenIdException {
    if (handle == null) {
      throw new OpenIdException("Missing " +
        CheckAuthenticationRequest.OPENID_ASSOC_HANDLE);
    }
  }

  @Override
  public Response processUsing(ServerInfo si) throws OpenIdException {
    String invalidate = null;
    Store store = si.getStore();
    String nonceStr = ar.getNonce();
    if (nonceStr != null) {
      Nonce n = store.findNonce(nonceStr);
      if (n != null) {
        String s = "Nonce has already been checked";
        log.debug(s);
        throw new OpenIdException(s);
      } else {
        n = store.generateNonce(nonceStr);
        store.saveNonce(n);
      }
    }
    Association assoc = store.findAssociation(handle);
    if ((assoc == null) || (assoc.hasExpired())) {
      invalidate = handle;
    }
    Crypto crypto = si.getCrypto();
    return new CheckAuthenticationResponse(ar, assoc, crypto, invalidate);
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("[CheckAuthenticationRequest ");
    s.append(super.toString());
    s.append(", handle=");
    s.append(handle);
    s.append(", authentication response=");
    s.append(ar);
    s.append("]");
    return s.toString();
  }

  @Override
  public Map<String,String> toMap() {
    Map<String,String> map = ar.toMap();
    map.putAll(super.toMap());
    return map;
  }
}
