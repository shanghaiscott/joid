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

/**
 * Information about this server.
 */
public class ServerInfo {

  private String urlEndPoint;
  private Store store;
  private Crypto crypto;

  /**
   * Creates an instance of the server information.
   *
   * @param urlEndPoint the URL endpoint for the service.
   * @param store the store implementation to use.
   * @param crypto the crypto implementation to use.
   */
  public ServerInfo(String urlEndPoint, Store store, Crypto crypto) {
    this.urlEndPoint = urlEndPoint;
    this.store = store;
    this.crypto = crypto;
  }

  public String getUrlEndPoint() {
    return urlEndPoint;
  }

  public Store getStore() {
    return store;
  }

  public Crypto getCrypto() {
    return crypto;
  }
}
