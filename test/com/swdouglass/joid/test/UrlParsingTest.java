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
package com.swdouglass.joid.test;

import org.junit.Test;
import static org.junit.Assert.*;
import com.swdouglass.joid.consumer.ServerAndDelegate;
import com.swdouglass.joid.consumer.Discoverer;

/**
 * 
 */
public class UrlParsingTest {

  @Test
  public void testGettingServerAndDelegate() throws Exception {
    Discoverer discoverer = new Discoverer();

    ServerAndDelegate serverAndDelegate = discoverer.findIdServer(
      "http://netevil.org/blog/2007/06/howto-set-yourself-up-with-an-openid");
    System.out.println(serverAndDelegate);
    assertEquals("https://pip.verisignlabs.com/server", serverAndDelegate.getServer());
    assertEquals("http://wezfurlong.pip.verisignlabs.com/", serverAndDelegate.getDelegate());

    serverAndDelegate = discoverer.findIdServer(
      "http://www.windley.com/archives/2007/02/using_openid_delegation.shtml");
    System.out.println(serverAndDelegate);
    assertEquals("https://www.signon.com/partner/openid", serverAndDelegate.getServer());
    assertEquals("https://windley.signon.com", serverAndDelegate.getDelegate());
  }

  @Test
  public void testYadisDiscovery() throws Exception {
    Discoverer discoverer = new Discoverer();
    ServerAndDelegate serverAndDelegate = new ServerAndDelegate();
    //discoverer.findWithYadis("http://www.yahoo.com", serverAndDelegate);
    discoverer.findWithYadis("https://www.google.com/accounts/o8/id", serverAndDelegate);
    System.out.println(serverAndDelegate);
    assertEquals("https://www.google.com/accounts/o8/ud", serverAndDelegate.getServer());
    assertEquals(null, serverAndDelegate.getDelegate());
  }
}
