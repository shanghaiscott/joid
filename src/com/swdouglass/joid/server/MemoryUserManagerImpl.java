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
package com.swdouglass.joid.server;

import java.util.HashMap;
import java.util.Map;

/**
 * Implements {@link UserManager} using {@link HashMap}.
 *
 */
public class MemoryUserManagerImpl implements UserManager {

  private Map<String, User> userMap = new HashMap<String, User>();
  private Map<String, String> rememberMeMap = new HashMap<String, String>();

  @Override
  public User getUser(String username) {
    return userMap.get(username);
  }

  @Override
  public void save(User user) {
    userMap.put(user.getUsername(), user);
  }

  @Override
  public void remember(String username, String authKey) {
    rememberMeMap.put(username, authKey);
  }

  @Override
  public String getRememberedUser(String username, String authKey) {
    String result = null;
    if (!(username == null || authKey == null)) {
      String auth = rememberMeMap.get(username);
      if (auth != null) {
        if (authKey.equals(auth)) {
          // then we have a match
          result = username;
        }
      }
    }
    return result;
  }

  /**
   *
   *
   * @param username
   * @param claimedId
   * @return
   */
  @Override
  public boolean canClaim(String username, String claimedId) {
    boolean result = false;
    String usernameFromClaimedId = claimedId.substring(claimedId.lastIndexOf("/") + 1);
    if (username.equals(usernameFromClaimedId)) {
      result = true;
    }
    return result;
  }

  @Override
  public boolean login(String inUserName, String inPassword) {
    boolean auth = false;
    if (getUser(inUserName).getPassword().equals(inPassword)) {
      auth = true;
    }
    return auth;
  }

  @Override
  public boolean canClaim(User user, String claimedId) {
    return canClaim(user.getUsername(), claimedId);
  }

}
