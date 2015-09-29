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

import java.util.Set;

/**
 *
 */
public class User implements java.io.Serializable {
  private static final long serialVersionUID = -8438752004953511721L;
  private Long id;
	private String password;
	private String username;
  /** List of valid OpenIDs. Used only by the DirectoryUserManagerImpl. */
  private Set<String> openIDs;


	public User() {
	}

	public User(String username, String password) {
		this.username = username;
		this.password = password;
	}


	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

  @Override
	public String toString() {
		return username;
	}

  /**
   * @return the id
   */
  public Long getId() {
    return id;
  }

  /**
   * @param id the id to set
   */
  public void setId(Long id) {
    this.id = id;
  }

  /**
   * @return the openIDs
   */
  public Set<String> getOpenIDs() {
    return openIDs;
  }

  /**
   * @param openIDs the openIDs to set
   */
  public void setOpenIDs(Set<String> openIDs) {
    this.openIDs = openIDs;
  }
}
