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

import com.swdouglass.joid.util.DependencyUtils;
import java.util.Date;

/**
 * Represents a store that is used by JOID for persisting associations.
 */
public abstract class Store {

  public static long DEFAULT_LIFESPAN = 600;
  private long associationLifetime = DEFAULT_LIFESPAN;

  /**
   * Override constructor in the Store implementation.
   */
  protected Store() {
  }
  
  /**
   * Gets a store implementation.
   *
   * @param className the class name of the store to instantiate.
   * @return the store.
   * @throws IllegalArgumentException if the class doesn't exist or is
   *  not a store type.
   */
  public static Store getInstance(String className) {
    return (Store) DependencyUtils.newInstance(className);
  }

  /**
   * Generates and returns association. To store the association
   * use {@link Store#saveAssociation(Association) saveAssociation()}
   *
   * @param req the association request.
   * @param crypto the crypto implementation to use.
   * @return the generated assocation.
   *
   * @throws OpenIdException at unrecoverable errors.
   */
  public Association generateAssociation(AssociationRequest req, Crypto crypto)
  throws OpenIdException {
    Association a = new Association();
    a.setHandle(Crypto.generateHandle());
    a.setSessionType(req.getSessionType());

    byte[] secret = null;
    if (req.isNotEncrypted()) {
      secret = crypto.generateRandom(req.getAssociationType());
    } else {
      secret = crypto.generateRandom(req.getSessionType());
      crypto.setDiffieHellman(req.getDhModulus(), req.getDhGenerator());
      byte[] encryptedSecret = crypto.encryptSecret(req.getDhConsumerPublic(), secret);
      a.setEncryptedMacKey(encryptedSecret);
      a.setPublicDhKey(crypto.getPublicKey());
    }
    a.setMacKey(secret);
    a.setIssuedDate(new Date());
    // lifetime in seconds
    a.setLifetime(new Long(associationLifetime));

    a.setAssociationType(req.getAssociationType());
    return a;
  }

  /**
   * Generates and returns a nonce. To store the nonce
   * use {@link Store#saveNonce(Nonce) saveNonce()}
   *
   * @param nonce the nonce to use.
   * @return the generated nonce.
   *
   * @throws OpenIdException at unrecoverable errors.
   */
  public Nonce generateNonce(String nonce) throws OpenIdException {
    Nonce n = new Nonce();
    n.setNonce(nonce);
    n.setCheckedDate(new Date());
    return n;
  }
  
  /**
   * Deletes an association from the store.
   *
   * @param a the association to delete.
   */
  public abstract void deleteAssociation(Association a) throws OpenIdException;

  /**
   * Saves an association in the store.
   *
   * @param a the association to store.
   */
  public abstract void saveAssociation(Association a) throws OpenIdException;

  /**
   * Finds an association in the store.
   *
   * @param handle the handle of the association to find.
   * @return the assocation if found; null otherwise.
   *
   * @throws OpenIdException at unrecoverable errors.
   */
  public abstract Association findAssociation(String handle) throws OpenIdException;

  /**
   * Finds a nonce in the store.
   *
   * @param nonce the nonce to find.
   * @return the nonce if found; null otherwise.
   *
   * @throws OpenIdException at unrecoverable errors.
   */
  public abstract Nonce findNonce(String nonce) throws OpenIdException;

  /**
   * Saves an nonce in the store.
   *
   * @param n the nonce to store.
   */
  public abstract void saveNonce(Nonce n) throws OpenIdException;

  /**
   * @return the associationLifetime
   */
  public long getAssociationLifetime() {
    return associationLifetime;
  }

  /**
   * @param associationLifetime the associationLifetime to set
   */
  public void setAssociationLifetime(long associationLifetime) {
    this.associationLifetime = associationLifetime;
  }
}
