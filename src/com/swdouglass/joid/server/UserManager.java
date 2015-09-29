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

/**
 * 
 */
public interface UserManager {
    User getUser(String username);
    void save(User user);

    /**
     * The implementation should store this relationship so it can retrieve it later
     * for auto login.
     * @param username
     * @param authKey
     */
    void remember(String username, String authKey);

    /**
     * Returns a User based on a generated authKey from a user selecting "Remember Me".
     * @param username
     * @param authKey
     * @return
     */
    String getRememberedUser(String username, String authKey);

    /**
     * 
     * @param username
     * @param claimedIdentity
     * @return
     */
    boolean canClaim(String username, String claimedIdentity);

    boolean canClaim(User user, String claimedIdentity);

    boolean login(String inUserName, String inPassword);
}
