/*
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
 */

package com.swdouglass.joid.server;

import com.swdouglass.joid.util.HibernateUtil;
import java.util.List;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hibernate.Query;
import org.hibernate.Session;
import org.hibernate.Transaction;

/**
 * Implements a persistent {@link UserManager} with
 * <a href="http://www.hibernate.org/">Hibernate</a>.
 *
 * @author scott
 */
public class HibernateUserManagerImpl extends MemoryUserManagerImpl implements UserManager {

  private final static Log log = LogFactory.getLog(HibernateUserManagerImpl.class);

  @Override
  public User getUser(String username) {
    User user = null;
    Session session = HibernateUtil.currentSession();
    Transaction tx = session.beginTransaction();

    String s = "from User as a where a.username=:username";
    Query q = session.createQuery(s);
    q.setParameter("username", username);
    List l = q.list();
    if (l.size() > 1) {
      log.warn("Non-unique username: " + username);
    }
    tx.commit();
    HibernateUtil.closeSession();

    if (l.size() == 0) {
      log.debug("Found no such username: " + username);
    } else {
      user = (User) l.get(0);
    }
    return user;
  }

  @Override
  public void save(User user) {
    Session session = HibernateUtil.currentSession();
    Transaction tx = session.beginTransaction();
    session.save(user);
    tx.commit();
    HibernateUtil.closeSession();
  }

}
