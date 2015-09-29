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
package com.swdouglass.joid.store;

import com.swdouglass.joid.OpenIdException;
import com.swdouglass.joid.Store;
import com.swdouglass.joid.Association;
import com.swdouglass.joid.Nonce;
import java.util.ArrayList;
import java.util.List;

public class MemoryStoreImpl extends Store {

  private static List<Association> associationList = new ArrayList<Association>();
  private static List<Nonce> nonceList = new ArrayList<Nonce>();

  @Override
  public void saveAssociation(Association a) {
    associationList.add(a);
  }

  @Override
  public void saveNonce(Nonce n) {
    nonceList.add(n);
  }

  @Override
  public void deleteAssociation(Association a) {
    throw new RuntimeException("not yet implemented");
  // "associationList.delete(a)"
  }

  @Override
  public Association findAssociation(String handle) throws OpenIdException {
    Association a = null;
    if (handle != null) {
      for (Association x : associationList) {
        if (handle.equals(x.getHandle())) {
          a = x;
          break;
        }
      }
    }
    return a;
  }

  @Override
  public Nonce findNonce(String nonce) throws OpenIdException {
    Nonce n = null;
    if (nonce != null) {
      for (Nonce x : nonceList) {
        if (nonce.equals(x.getNonce())) {
          n = x;
          break;
        }
      }
    }
    return n;
  }

}
