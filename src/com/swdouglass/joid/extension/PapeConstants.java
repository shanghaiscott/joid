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
package com.swdouglass.joid.extension;

/**
 * Provider Authentication Policy Extension constants from the
 * <a href="http://openid.net/specs/openid-provider-authentication-policy-extension-1_0-02.html">specification</a>.
 */
public interface PapeConstants {

  /**
   * PAPE namespace
   */
  String PAPE_NAMESPACE = "http://specs.openid.net/extensions/pape/1.0";
  /**
   * Preferred PAPE namespace identifier
   */
  String PAPE_IDENTIFIER = "pape";
  /**
   * Phishing-Resistant authentication policy
   */
  String AUTH_PHISHING_RESISTANT = "http://schemas.openid.net/pape/policies/2007/06/phishing-resistant";
  /**
   * Multi-Factor authentication policy
   */
  String AUTH_MULTI_FACTOR = "http://schemas.openid.net/pape/policies/2007/06/multi-factor";
  /**
   * Physical Multi-Factor authentication policy
   */
  String AUTH_PHYSICAL_MULTI_FACTOR = "http://schemas.openid.net/pape/policies/2007/06/multi-factor-physical";
}
