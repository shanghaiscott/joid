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

package com.swdouglass.joid.consumer;

import java.util.Set;

public class XRDSService implements java.io.Serializable {
  private static final long serialVersionUID = 8417858482283280508L;

  private String uri;
  private String openIDDelegate;
  private Set<String> type;


  public void setUri(String uri) {
    this.uri = uri;
  }

  public String getUri() {
    return uri;
  }

  /**
   * @return the openIDDelegate
   */
  public String getOpenIDDelegate() {
    return openIDDelegate;
  }

  /**
   * @param openIDDelegate the openIDDelegate to set
   */
  public void setOpenIDDelegate(String openIDDelegate) {
    this.openIDDelegate = openIDDelegate;
  }

  /**
   * @return the type
   */
  public Set<String> getType() {
    return type;
  }

  /**
   * @param type the type to set
   */
  public void setType(Set<String> type) {
    this.type = type;
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("[XRDSService: ");
    sb.append("URI=");
    sb.append(getUri());
    sb.append(", openid:Delegate=");
    sb.append(getOpenIDDelegate());
    sb.append(", Types={ ");
    for (String t: getType()) {
      sb.append(t);
      sb.append(" ");
    }
    sb.append("}]");
    return sb.toString();
  }

}
