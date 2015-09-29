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
package com.swdouglass.joid.util;

import org.hibernate.HibernateException;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.cfg.Configuration;

/**
 * Manages Hibernate connections to our underlying database.
 *
 * Typical usecase:
 * <pre>
 * Session session = HibernateUtil.currentSession();
 * Transaction tx = session.beginTransaction();
 * ... do something with session ...
 * tx.commit();
 * HibernateUtil.closeSession();
 * </pre>
 */
public class HibernateUtil {

  private static final SessionFactory sessionFactory;

  private HibernateUtil() {
  }


  static {
    try {
      Configuration config = new Configuration();
      config.configure("hibernate.cfg.xml");
      sessionFactory = config.buildSessionFactory();
    } catch (Throwable ex) {
      // Make sure you log the exception, as it might be swallowed
      ex.printStackTrace();
      System.err.println("Initial SessionFactory creation failed." + ex);
      throw new ExceptionInInitializerError(ex);
    }
  }
  
  private static final ThreadLocal session = new ThreadLocal();

  /**
   * Returns the current database session. Opens a new session, if this
   * thread has none yet.
   *
   * @return the current database session.
   *
   * @throws HibernateException if the Hibernate layer chokes.
   */
  @SuppressWarnings("unchecked")
  public static Session currentSession() throws HibernateException {
    Session s = (Session) session.get();
    if (s == null) {
      s = sessionFactory.openSession();
      session.set(s);
    }
    return s;
  }

  /**
   * Closes the current database session.
   *
   * @throws HibernateException if the Hibernate layer chokes.
   */
  @SuppressWarnings("unchecked")
  public static void closeSession() throws HibernateException {
    Session s = (Session) session.get();
    session.set(null);
    if (s != null) {
      s.close();
    }
  }
}