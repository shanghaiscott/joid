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

/**
 * Represents an OpenID response. Valid for OpenID 1.1 and 2.0 namespace.
 */
public abstract class Response extends Message {

  static String OPENID_ERROR = "openid.error";
  String error;

  String getError() {
    return error;
  }

  @Override
  Map<String,String> toMap() {
    return super.toMap();
  }

  Response(Map<String,String> map) {
    if (map != null) {
      this.ns = map.get(Message.OPENID_NS);
      this.error = map.get(Response.OPENID_ERROR);
    }
  }

  /**
   * Returns a string representation of this response.
   *
   * @return a string representation of this response.
   */
  @Override
  public String toString() {
    String s = super.toString();
    if (error != null) {
      s += ", error=" + error;
    }
    return s;
  }
}
