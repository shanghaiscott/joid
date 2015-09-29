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
package com.swdouglass.joid.store;

import com.swdouglass.joid.util.HibernateUtil;
import java.util.List;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.logging.Log;
import org.hibernate.Query;
import org.hibernate.Session;
import org.hibernate.Transaction;
import com.swdouglass.joid.OpenIdException;
import com.swdouglass.joid.Store;
import com.swdouglass.joid.Association;
import com.swdouglass.joid.Nonce;

/**
 * A database backed store.
 */
public class HibernateStoreImpl extends Store {

  private final static Log log = LogFactory.getLog(HibernateStoreImpl.class);

  @Override
  public void saveNonce(Nonce n) {
    Session session = HibernateUtil.currentSession();
    Transaction tx = session.beginTransaction();
    session.save(n);
    tx.commit();
    HibernateUtil.closeSession();
  }

  @Override
  public void saveAssociation(Association a) {
    Session session = HibernateUtil.currentSession();
    Transaction tx = session.beginTransaction();
    session.save(a);
    tx.commit();
    HibernateUtil.closeSession();
  }

  @Override
  public void deleteAssociation(Association a) {
    Session session = HibernateUtil.currentSession();
    session.delete(a);
  }

  @Override
  public Association findAssociation(String handle)
  throws OpenIdException {
    Session session = HibernateUtil.currentSession();
    Transaction tx = session.beginTransaction();

    String s = "from Association as a where a.handle=:handle";
    Query q = session.createQuery(s);
    q.setParameter("handle", handle);
    List l = q.list();
    if (l.size() > 1) {
      throw new OpenIdException("Non-unique association handle: " + handle);
    }
    tx.commit();
    HibernateUtil.closeSession();

    if (l.size() == 0) {
      log.debug("Found no such association: " + handle);
      return null;
    } else {
      return (Association) l.get(0);
    }
  }

  @Override
  public Nonce findNonce(String nonce)
  throws OpenIdException {
    Session session = HibernateUtil.currentSession();
    Transaction tx = session.beginTransaction();

    String s = "from Nonce as n where n.nonce=:nonce";
    Query q = session.createQuery(s);
    q.setParameter("nonce", nonce);
    List l = q.list();
    if (l.size() > 1) {
      throw new OpenIdException("Non-unique nonce: " + nonce);
    }
    tx.commit();
    HibernateUtil.closeSession();

    if (l.size() == 0) {
      log.debug("Found no such nonce: " + nonce);
      return null;
    } else {
      return (Nonce) l.get(0);
    }
  }
}
