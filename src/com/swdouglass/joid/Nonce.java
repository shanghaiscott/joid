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
package com.swdouglass.joid;

import java.util.Date;

public class Nonce implements java.io.Serializable {
  private static final long serialVersionUID = 9163383425337631809L;

  private Long id;
  private String nonce;
  private Date checkedDate;

  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public String getNonce() {
    return nonce;
  }

  public void setNonce(String s) {
    nonce = s;
  }

  public Date getCheckedDate() {
    return checkedDate;
  }

  public void setCheckedDate(Date date) {
    this.checkedDate = date;
  }

  /**
   * Returns a string representation of this nonce.
   *
   * @return a string representation of this nonce.
   */
  @Override
  public String toString() {
    StringBuilder s = new StringBuilder("[Nonce nonce=");
    s.append(nonce);
    s.append(", checked=");
    s.append(checkedDate);
    s.append("]");
    return s.toString();
  }
}
