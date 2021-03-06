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

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Represents an OpenID message. 
 */
public abstract class Message {

  String mode;
  String ns;
  static String OPENID_20_NAMESPACE = "http://specs.openid.net/auth/2.0";
  static String OPENID_NS = "openid.ns";
  static String OPENID_MODE = "openid.mode";
  static Set OPENID_RESERVED_WORDS;

  static {
    // from section 12 in spec
    OPENID_RESERVED_WORDS = new HashSet<String>(Arrays.asList(new String[]{
        "assoc_handle", "assoc_type", "claimed_id", "contact", "delegate",
        "dh_consumer_public", "dh_gen", "dh_modulus", "error", "identity",
        "invalidate_handle", "mode", "ns", "op_endpoint", "openid", "realm",
        "reference", "response_nonce", "return_to", "server", "session_type",
        "sig", "signed", "trust_root"}));
  }

  /**
   * Returns whether this request is an OpenID 2.0 request.
   *
   * @return true if this request is an OpenID 2.0 request.
   */
  public boolean isVersion2() {
    return OPENID_20_NAMESPACE.equals(this.ns);
  }

  /**
   * Returns the namespace of this message. For OpenID 2.0 messages,
   * this namespace will be <code>http://specs.openid.net/auth/2.0</code>.
   *
   * @return the namespace, or null if none (OpenID 1.x).
   */
  public String getNamespace() {
    return ns;
  }

  /**
   * Returns a string representation of this message.
   *
   * @return a string representation of this message.
   */
  @Override
  public String toString() {
    StringBuilder s = new StringBuilder("version=");
    if (isVersion2()) {
      s.append("2.0");
    } else {
      s.append("1.x");
    }
    if (ns != null) {
      s.append(", namespace=");
      s.append(ns);
    }
    return s.toString();
  }

  /**
   * Unrolls this message as a string. This string will use the
   * <code>name:value</code> format of the specification. See also
   * {@link #toUrlString()}.
   *
   * @return the message as a string.
   */
  public String toPostString() throws OpenIdException {
    return MessageParser.toPostString(this);
  }

  /**
   * Unrolls this message as a string. This string will use encoding
   * suitable for URLs. See also {@link #toPostString()}.
   *
   * @return the message as a string.
   */
  public String toUrlString() throws OpenIdException {
    return MessageParser.toUrlString(this);
  }

  Map<String, String> toMap() {
    Map<String, String> map = new HashMap<String, String>();
    if (ns != null) {
      map.put(Message.OPENID_NS, ns);
    }
    if (mode != null) {
      map.put(Message.OPENID_MODE, mode);
    }
    return map;
  }

}
