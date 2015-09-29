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
 * Represents an OpenID request. Valid for OpenID 1.1 and 2.0 namespace.
 */
public abstract class Request extends Message {

  Request(Map<String,String> map, String mode) {
    this.mode = mode;

    if (map != null) {
      this.ns = map.get(Message.OPENID_NS);
    }
  }

  @Override
  public Map<String,String> toMap() {
    return super.toMap();
  }

  /**
   * Processes this request using the given store and crypto implementations.
   * This processing step should produce a valid response that can be
   * sent back to the requestor. Associations may be read from, written to,
   * or deleted from the store by way of this processing step.
   *
   * @param serverInfo information about this server's implementation.
   *
   * @return the response
   *
   * @throws OpenIdException unrecoverable errors happen.
   */
  public abstract Response processUsing(ServerInfo serverInfo)
  throws OpenIdException;
}
