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
 */

package com.swdouglass.joid.consumer;

import com.swdouglass.joid.AuthenticationResponse;

/**
 * This class is returned by JoidConsumer.authenticate() and is just a holder for
 * the results.
 */
public class AuthenticationResult {

  private boolean successful;
  private String identity;
  private AuthenticationResponse response;

  public AuthenticationResult(String identity, AuthenticationResponse response) {
    this.identity = identity;
    this.response = response;
    if (identity != null) {
      successful = true;
    }
  }

  public AuthenticationResponse getResponse() {
    return response;
  }

  public void setResponse(AuthenticationResponse response) {
    this.response = response;
  }

  public String getIdentity() {
    return identity;
  }

  public void setIdentity(String identity) {
    this.identity = identity;
  }

  public boolean isSuccessful() {
    return successful;
  }

  public void setSuccessful(boolean successful) {
    this.successful = successful;
  }
}
