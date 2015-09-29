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
import java.util.Calendar;
import java.math.BigInteger;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class Association implements java.io.Serializable {

  private final static Log log = LogFactory.getLog(Association.class);
  private static final long serialVersionUID = 9209717219429261893L;
  private Long id;
  private String handle;
  private String secret;
  private Date issuedDate;
  private Long lifetime;
  private String associationType;
  private String error;
  private String sessionType;
  private byte[] encryptedMacKey;
  private BigInteger publicKey;

  public boolean isSuccessful() {
    return (error == null);
  }

  public boolean isEncrypted() {
    return ((AssociationRequest.DH_SHA1.equals(sessionType)) ||
      (AssociationRequest.DH_SHA256.equals(sessionType)));
  }

  public Long getId() {
    return id;
  }

  public String getSecret() {
    return secret;
  }

  public void setSecret(String secret) {
    this.secret = secret;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public String getHandle() {
    return handle;
  }

  public void setHandle(String s) {
    this.handle = s;
  }

  public Date getIssuedDate() {
    return issuedDate;
  }

  public void setIssuedDate(Date issuedDate) {
    //SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    //Date tmp = issuedDate;
    //sdf.format(tmp);
    //this.issuedDate = tmp;
    this.issuedDate = issuedDate;
  }

  public Long getLifetime() {
    return lifetime;
  }

  /**
   *
   * @param lifetime in seconds for this association. Expires after.
   */
  public void setLifetime(Long lifetime) {
    this.lifetime = lifetime;
  }

  public String getAssociationType() {
    return associationType;
  }

  public void setAssociationType(String s) {
    this.associationType = s;
  }

  /**
   * Returns a string representation of this assocation.
   *
   * @return a string representation of this assocation.
   */
  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    s.append("[Association secret=");
    s.append(secret);
    if (encryptedMacKey != null) {
      s.append(", encrypted secret=");
      s.append(Crypto.convertToString(encryptedMacKey));
    }
    if (publicKey != null) {
      s.append(", public key=");
      s.append(Crypto.convertToString(publicKey));
    }
    s.append(", type=");
    s.append(associationType);
    s.append(", issuedDate=");
    s.append(issuedDate);
    s.append("]");
    return s.toString();
  }

  public String getError() {
    return error;
  }

  public String getErrorCode() {
    throw new UnsupportedOperationException("Not supported yet.");
  }

  public void setSessionType(String sessionType) {
    this.sessionType = sessionType;
  }

  public String getSessionType() {
    return sessionType;
  }

  public void setMacKey(byte[] macKey) {
    this.secret = Crypto.convertToString(macKey);
  }

  public byte[] getMacKey() {
    return Crypto.convertToBytes(secret);
  }

  public void setEncryptedMacKey(byte[] b) {
    encryptedMacKey = b;
  }

  public byte[] getEncryptedMacKey() {
    return encryptedMacKey;
  }

  public void setPublicDhKey(BigInteger pk) {
    publicKey = pk;
  }

  public BigInteger getPublicDhKey() {
    return publicKey;
  }

  public boolean hasExpired() {
    Calendar now = Calendar.getInstance();
    Calendar expired = Calendar.getInstance();
    expired.setTime(issuedDate);
    expired.add(Calendar.SECOND, lifetime.intValue());
    if (log.isDebugEnabled()) {
      log.debug("now: " + now.toString());
      log.debug("issuedDate: " + issuedDate.toString());
      log.debug("expired: " + expired.toString());
      log.debug("now.after(expired): " + now.after(expired));
    }
    return now.after(expired);
  }
}
