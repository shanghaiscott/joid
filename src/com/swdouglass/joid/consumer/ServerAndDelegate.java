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

public class ServerAndDelegate implements java.io.Serializable {
  private static final long serialVersionUID = -1796770985117488386L;

  private String server;
  private String delegate;

  public String getServer() {
    return server;
  }

  public void setServer(String server) {
    this.server = server;
  }

  public String getDelegate() {
    return delegate;
  }

  public void setDelegate(String delegate) {
    this.delegate = delegate;
  }

  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("ServerAndDelegate[server=");
    s.append(server);
    s.append(", delegate=");
    s.append(delegate);
    s.append("]");
    return s.toString();
  }
}
