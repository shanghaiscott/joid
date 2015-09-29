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

import java.util.List;
import java.util.ArrayList;

public class XRDSDocument implements java.io.Serializable {
  private static final long serialVersionUID = -7561684020842022190L;

  private List<XRDSService> serviceList = new ArrayList<XRDSService>();

  public List<XRDSService> getServiceList() {
    return serviceList;
  }

  public void setServiceList(List<XRDSService> serviceList) {
    this.serviceList = serviceList;
  }

  public void addService(XRDSService service) {
    serviceList.add(service);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder("[Services: \n");
    for (XRDSService service: getServiceList()) {
      sb.append(service.toString());
      sb.append("\n");
    }
    sb.append("]");
    return sb.toString();
  }
}
