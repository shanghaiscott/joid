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
 * The main exception class of the OpenId librbary.
 */
public class OpenIdException extends Exception {

  private static final long serialVersionUID = 28732439387623L;

  /**
   * Creates an exception.
   * @param s a string value to encapsulate.
   */
  public OpenIdException(String s) {
    super(s);
  }

  /**
   * Creates an exception.
   * @param e a exception to encapsulate.
   */
  public OpenIdException(Exception e) {
    super(e);
  }

  public OpenIdException(String s, Exception e) {
    super(s, e);
  }

  /**
   * Returns this exception's message.
   * @return a string message of this exception (either the encapsulated string,
   * or the encapsulated exception).
   */
  @Override
  public String getMessage() {
    Throwable t = getCause();
    if (t != null) {
      return t.getMessage();
    } else {
      return super.getMessage();
    }
  }
}
