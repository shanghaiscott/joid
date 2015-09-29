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
package com.swdouglass.joid.test;

import com.swdouglass.joid.AssociationRequest;
import com.swdouglass.joid.AssociationResponse;
import com.swdouglass.joid.AuthenticationRequest;
import com.swdouglass.joid.AuthenticationResponse;
import com.swdouglass.joid.CheckAuthenticationRequest;
import com.swdouglass.joid.CheckAuthenticationResponse;
import com.swdouglass.joid.Crypto;
import com.swdouglass.joid.DiffieHellman;
import com.swdouglass.joid.MessageParser;
import com.swdouglass.joid.OpenId;
import com.swdouglass.joid.OpenIdException;
import com.swdouglass.joid.Request;
import com.swdouglass.joid.Response;
import com.swdouglass.joid.MessageFactory;
import com.swdouglass.joid.ServerInfo;
import com.swdouglass.joid.extension.SimpleRegistration;
import com.swdouglass.joid.Store;
import com.swdouglass.joid.extension.PapeRequest;
import com.swdouglass.joid.extension.PapeResponse;
import com.swdouglass.joid.Association;
import com.swdouglass.joid.store.MemoryStoreImpl;
import java.math.BigInteger;
import java.net.URLEncoder;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

public class JoidTest {

  private long defaultLifespan;
  private static Crypto crypto = new Crypto();
  private static Store store = Store.getInstance(MemoryStoreImpl.class.getName());
  private static ServerInfo serverInfo = new ServerInfo("http://example.com",
    store, crypto);

  private static final SecureRandom srand;

  static {
    try {
      srand = SecureRandom.getInstance("SHA1PRNG");
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("No SHA1 prng??");
    }
  }
  BigInteger p = DiffieHellman.DEFAULT_MODULUS;
  BigInteger g = DiffieHellman.DEFAULT_GENERATOR;

  public JoidTest() {
  }

  @BeforeClass
  public static void setUpClass() throws Exception {
  }

  @AfterClass
  public static void tearDownClass() throws Exception {
  }

  @Before
  public void setUp() throws Exception {
    defaultLifespan = MemoryStoreImpl.DEFAULT_LIFESPAN;
  }

  @After
  public void tearDown() throws Exception {
  }

  private AssociationResponse associate(DiffieHellman dh)
          throws Exception {
    BigInteger publicKey = dh.getPublicKey();

    String s = "openid.mode=associate&openid.assoc_type=HMAC-SHA1" +
      "&openid.session_type=DH-SHA1&openid.dh_consumer_public=";

    s += URLEncoder.encode(Crypto.convertToString(publicKey), "UTF-8");

    Request req = MessageFactory.parseRequest(s);
    assertTrue(req instanceof AssociationRequest);
    Response resp = req.processUsing(serverInfo);
    assertTrue(resp instanceof AssociationResponse);
    s = resp.toUrlString();

    Response resp2 = MessageFactory.parseResponse(s);
    assertTrue(resp2 instanceof AssociationResponse);
    AssociationResponse ar = (AssociationResponse) resp;
    return ar;
  }

  private AssociationResponse associate256(DiffieHellman dh) throws Exception {
    BigInteger publicKey = dh.getPublicKey();

    String s = "openid.mode=associate&openid.assoc_type=HMAC-SHA256" +
      "&openid.session_type=DH-SHA1&openid.dh_consumer_public=";

    s += URLEncoder.encode(Crypto.convertToString(publicKey), "UTF-8");

    Request req = MessageFactory.parseRequest(s);
    assertTrue(req instanceof AssociationRequest);

    Response resp = req.processUsing(serverInfo);
    assertTrue(resp instanceof AssociationResponse);
    AssociationResponse foo = (AssociationResponse) resp;
    assertTrue(foo.getSessionType(),
            "DH-SHA256".equals(foo.getSessionType()));
    assertTrue("HMAC-SHA256".equals(foo.getAssociationType()));
    s = resp.toUrlString();

    Response resp2 = MessageFactory.parseResponse(s);
    assertTrue(resp2 instanceof AssociationResponse);
    AssociationResponse ar = (AssociationResponse) resp;
    return ar;
  }

  @Test
  public void testUrlToMap() throws Exception {
    String testStr = "path?foo=bar&baz=qux";
    Map map = MessageParser.urlEncodedToMap(testStr);
    assertTrue(map.size() == 2);
    assertTrue(((String) map.get("foo")).equals("bar"));
    assertTrue(((String) map.get("baz")).equals("qux"));
    testStr = "path?foo=bar;baz=qux";
    map = MessageParser.urlEncodedToMap(testStr);
    assertTrue(map.size() == 2);
    assertTrue(((String) map.get("foo")).equals("bar"));
    assertTrue(((String) map.get("baz")).equals("qux"));
  }

  @Test
  public void testAssociationLifeLength() throws Exception {
    Association a = new Association();
    a.setIssuedDate(new Date());
    a.setLifetime(new Long(1));
    assertFalse(a.hasExpired());
    Thread.sleep(1200);
    assertTrue(a.hasExpired());
  }

  @Test
  public void testGetSharedSecret() {
    for (int i = 0; i < 3; i++) {
      DiffieHellman dh1 = new DiffieHellman(p, g);
      DiffieHellman dh2 = new DiffieHellman(p, g);

      BigInteger secret1 = dh1.getSharedSecret(dh2.getPublicKey());
      BigInteger secret2 = dh2.getSharedSecret(dh1.getPublicKey());

      assertEquals(secret1, secret2);
    }
  }

  @Test
  public void test2() throws Exception {
    String s = Utils.readFileAsString("test/data/2.txt");

    Request req = MessageFactory.parseRequest(s);
    assertTrue(req instanceof AssociationRequest);
    Response resp = req.processUsing(serverInfo);
    assertTrue(resp instanceof AssociationResponse);

    s = resp.toUrlString();

    Response resp2 = MessageFactory.parseResponse(s);
    assertTrue(resp2 instanceof AssociationResponse);
    AssociationResponse ar = (AssociationResponse) resp2;

    assertTrue(ar.getSessionType(), "DH-SHA1".equals(ar.getSessionType()));
    assertTrue("HMAC-SHA1".equals(ar.getAssociationType()));
    assertTrue(defaultLifespan == ar.getExpiresIn());
    assertTrue(null == ar.getMacKey());
    assertTrue(null != ar.getEncryptedMacKey());
    assertTrue(null != ar.getDhServerPublic());
    assertTrue(null == ar.getErrorCode());
  }

  @Test
  public void test2b() throws Exception {
    String s = Utils.readFileAsString("test/data/2.txt");

    OpenId openId = new OpenId(serverInfo);
    assertTrue(openId.isAssociationRequest(s));
    assertFalse(openId.isAuthenticationRequest(s));
  }

  // Test no encryption 1.1 association request
  @Test
  public void testAssocNoEncryption() throws Exception {
    String s = Utils.readFileAsString("test/data/5.txt");

    Request req = MessageFactory.parseRequest(s);
    assertTrue(req instanceof AssociationRequest);
    Response resp = req.processUsing(serverInfo);
    assertTrue(resp instanceof AssociationResponse);

    s = resp.toUrlString();

    Response resp2 = MessageFactory.parseResponse(s);
    assertTrue(resp2 instanceof AssociationResponse);
    AssociationResponse ar = (AssociationResponse) resp2;

    assertTrue(null == ar.getSessionType());
    assertTrue("HMAC-SHA1".equals(ar.getAssociationType()));
    assertTrue(defaultLifespan == ar.getExpiresIn());
    assertTrue(null != ar.getMacKey());
    assertTrue(null == ar.getEncryptedMacKey());
    assertTrue(null == ar.getDhServerPublic());
    assertTrue(null == ar.getErrorCode());
  }

  @Test
  public void testMarshall() throws Exception {
    DiffieHellman dh = new DiffieHellman(p, g);
    BigInteger privateKey = dh.getPrivateKey();
    BigInteger publicKey = dh.getPublicKey();
    String s = Crypto.convertToString(privateKey);
    BigInteger b = Crypto.convertToBigIntegerFromString(s);
    assertEquals(privateKey, b);
    s = Crypto.convertToString(publicKey);
    b = Crypto.convertToBigIntegerFromString(s);
    assertEquals(publicKey, b);
  }

  @Test
  public void testSchtuffTrustRoot() throws Exception {
    StringBuilder s = new StringBuilder();
    s.append("openid.identity=http%3A%2F%2Fhans.beta.abtain.com%2F");
    s.append("&openid.mode=checkid_setup");
    s.append("&openid.return_to=http%3A%2F%2Fwww.schtuff.com%2F%3Faction%3Dope");
    s.append("nid_return%26dest%3D%26stay_logged_in%3DFalse%26response_no");
    s.append("nce%3D2006-12-" + "06T04%253A54%253A51ZQvGYW3");
    s.append("&openid.trust_root=http%3A%2F%2F%2A.schtuff.com%2F");
    
    Request req = MessageFactory.parseRequest(s.toString());
    assertTrue(req instanceof AuthenticationRequest);
  }

  @Test
  public void testOpenIdNetDemoTrustRoot() throws Exception {
    StringBuilder s = new StringBuilder();
    s.append("openid.mode=checkid_setup&");
    s.append("openid.identity=http://hans.beta.abtain.com/&");
    s.append("openid.return_to=http://openid.net/demo/helpe");
    s.append("r.bml%3Fstyle%3Dclassic%26oic.time%3D11654216");
    s.append("99-368eacd1483709faab32&");
    s.append("openid.trust_root=http://%2A.openid.net/demo/&");
    s.append("openid.assoc_handle=1c431e80-8545-11db-9ff5-1");
    s.append("55b0e692653");
    Request req = MessageFactory.parseRequest(s.toString());
    assertTrue(req instanceof AuthenticationRequest);
  }

  @Test
  public void testTrustRoot() throws Exception {
    String base = "openid.mode=checkid_setup&openid.identity=" + "http://my.identity&openid.return_to=http://a.example.com";

    String foo = base + "&openid.trust_root=http://*.example.com";
    Request req = MessageFactory.parseRequest(foo);
    assertTrue(req instanceof AuthenticationRequest);

    foo = base + "&openid.trust_root=http://www.example.com";
    try {
      MessageFactory.parseRequest(foo);
      fail("Should have thrown");
    } catch (OpenIdException e) {
    }


    // Trust root     Return to
    // ----------     ---------
    // /a/b/c     =>  /a/b/c/d    ==> ok
    // /a/b/c     =>  /a/b        ==> not ok
    // /a/b/c     =>  /a/b/b      ==> not ok
    //

    base = "openid.mode=checkid_setup&openid.identity=" + "http://my.identity&openid.trust_root=http://example.com/a/b/c";

    foo = base + "&openid.return_to=http://example.com/a/b/c/d";
    req = MessageFactory.parseRequest(foo);
    assertTrue(req instanceof AuthenticationRequest);

    foo = base + "&openid.return_to=http://example.com/a/b";
    try {
      MessageFactory.parseRequest(foo);
      fail("Should have thrown");
    } catch (OpenIdException e) {
    }

    foo = base + "&openid.return_to=http://example.com/a/b/b";
    try {
      MessageFactory.parseRequest(foo);
      fail("Should have thrown");
    } catch (OpenIdException e) {
    }

  }

  @Test
  public void test3() throws Exception {
    DiffieHellman dh = new DiffieHellman(p, g);
    AssociationResponse ar = associate(dh);
    assertFalse(ar.isVersion2());

    assertTrue(ar.getSessionType(), "DH-SHA1".equals(ar.getSessionType()));
    assertTrue("HMAC-SHA1".equals(ar.getAssociationType()));
    assertTrue(defaultLifespan == ar.getExpiresIn());
    assertTrue(null == ar.getErrorCode());
    assertTrue(null == ar.getMacKey());

    byte[] encKey = ar.getEncryptedMacKey();
    assertTrue(null != encKey);

    BigInteger serverPublic = ar.getDhServerPublic();
    assertTrue(null != serverPublic);

    byte[] clearKey = dh.xorSecret(serverPublic, encKey);

    // authenticate
    String s = Utils.readFileAsString("test/data/3bv1.txt");
    s += "?openid.assoc_handle=" + URLEncoder.encode(ar.getAssociationHandle(), "UTF-8");

    Request req = MessageFactory.parseRequest(s);
    assertTrue(req instanceof AuthenticationRequest);
    assertFalse(req.isVersion2());
    Response resp = req.processUsing(serverInfo);
    assertTrue(resp instanceof AuthenticationResponse);
    assertFalse(resp.isVersion2());

    s = resp.toUrlString();

    Response resp2 = MessageFactory.parseResponse(s);
    assertTrue(resp2 instanceof AuthenticationResponse);
    AuthenticationResponse authr = (AuthenticationResponse) resp2;
    assertFalse(authr.isVersion2());
    assertTrue(null == authr.getUrlEndPoint());

    String sigList = authr.getSignedList();
    assertTrue(sigList != null);
    String signature = authr.getSignature();
    assertTrue(signature != null);

    String reSigned = authr.sign("HMAC-SHA1", clearKey, sigList);
    assertEquals(reSigned, signature);


    // check that we can authenticate the signature
    Map<String, String> map = authr.toMap();
    CheckAuthenticationRequest carq = new CheckAuthenticationRequest(map, "check_authentication");
    assertFalse(carq.isVersion2());

    resp = carq.processUsing(serverInfo);
    assertFalse(resp.isVersion2());
    assertTrue(resp instanceof CheckAuthenticationResponse);
    CheckAuthenticationResponse carp = (CheckAuthenticationResponse) resp;
    assertTrue(carp.isValid());
  }

  @Test
  public void test3_badsig() throws Exception {
    DiffieHellman dh = new DiffieHellman(p, g);
    AssociationResponse ar = associate(dh);
    assertFalse(ar.isVersion2());

    assertTrue(ar.getSessionType(), "DH-SHA1".equals(ar.getSessionType()));
    assertTrue("HMAC-SHA1".equals(ar.getAssociationType()));
    assertTrue(defaultLifespan == ar.getExpiresIn());
    assertTrue(null == ar.getErrorCode());
    assertTrue(null == ar.getMacKey());

    byte[] encKey = ar.getEncryptedMacKey();
    assertTrue(null != encKey);

    BigInteger serverPublic = ar.getDhServerPublic();
    assertTrue(null != serverPublic);

    byte[] clearKey = dh.xorSecret(serverPublic, encKey);

    // authenticate
    String s = Utils.readFileAsString("test/data/3bv1.txt");
    s += "?openid.assoc_handle=" + URLEncoder.encode(ar.getAssociationHandle(), "UTF-8");

    Request req = MessageFactory.parseRequest(s);
    assertTrue(req instanceof AuthenticationRequest);
    assertFalse(req.isVersion2());
    Response resp = req.processUsing(serverInfo);
    assertTrue(resp instanceof AuthenticationResponse);
    assertFalse(resp.isVersion2());

    s = resp.toUrlString();

    Response resp2 = MessageFactory.parseResponse(s);
    assertTrue(resp2 instanceof AuthenticationResponse);
    AuthenticationResponse authr = (AuthenticationResponse) resp2;
    assertFalse(authr.isVersion2());

    String sigList = authr.getSignedList();
    assertTrue(sigList != null);
    String signature = authr.getSignature();
    assertTrue(signature != null);

    String reSigned = authr.sign("HMAC-SHA1", clearKey, sigList);
    assertEquals(reSigned, signature);

    // check that the wrong signature doesn't authenticate
    Map<String, String> map = authr.toMap();
    map.put("openid.sig", "pO+52CAFEBABEuu0lVRivEeu2Zw=");
    CheckAuthenticationRequest carq = new CheckAuthenticationRequest(map, "check_authentication");

    resp = carq.processUsing(serverInfo);
    assertFalse(resp.isVersion2());
    assertTrue(resp instanceof CheckAuthenticationResponse);
    CheckAuthenticationResponse carp = (CheckAuthenticationResponse) resp;
    assertFalse(carp.isValid());
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testSreg() throws Exception {
    DiffieHellman dh = new DiffieHellman(p, g);
    AssociationResponse ar = associate(dh);

    assertTrue(ar.getSessionType(), "DH-SHA1".equals(ar.getSessionType()));
    assertTrue("HMAC-SHA1".equals(ar.getAssociationType()));
    assertTrue(defaultLifespan == ar.getExpiresIn());
    assertTrue(null == ar.getErrorCode());
    assertTrue(null == ar.getMacKey());

    byte[] encKey = ar.getEncryptedMacKey();
    assertTrue(null != encKey);

    BigInteger serverPublic = ar.getDhServerPublic();
    assertTrue(null != serverPublic);

    byte[] clearKey = dh.xorSecret(serverPublic, encKey);

    // authenticate
    String s = Utils.readFileAsString("test/data/sreg.txt");
    s += "?openid.assoc_handle=" + URLEncoder.encode(ar.getAssociationHandle(), "UTF-8");

    Request req = MessageFactory.parseRequest(s);
    assertTrue(req.isVersion2());
    assertTrue(req instanceof AuthenticationRequest);
    SimpleRegistration sreg = ((AuthenticationRequest) req).getSimpleRegistration();
    Set<String> set = sreg.getRequired();
    Map<String,String> supplied = new HashMap<String,String>();
    for (Iterator iter = set.iterator(); iter.hasNext();) {
      s = (String) iter.next();
      supplied.put(s, "blahblah");
    }
    sreg = new SimpleRegistration(set, Collections.EMPTY_SET, supplied, "");
    ((AuthenticationRequest) req).setSimpleRegistration(sreg);

    Response resp = req.processUsing(serverInfo);
    assertTrue(resp instanceof AuthenticationResponse);
    assertTrue(resp.isVersion2());

    s = resp.toUrlString();

    Response resp2 = MessageFactory.parseResponse(s);
    assertTrue(resp2 instanceof AuthenticationResponse);
    AuthenticationResponse authr = (AuthenticationResponse) resp2;
    assertTrue(authr.isVersion2());

    String sigList = authr.getSignedList();
    assertTrue(sigList != null);
    String signature = authr.getSignature();
    assertTrue(signature != null);

    String reSigned = authr.sign("HMAC-SHA1", clearKey, sigList);
    assertEquals(reSigned, signature);

    // check that we can authenticate the signaure
    Map<String,String> map = authr.toMap();
    CheckAuthenticationRequest carq = new CheckAuthenticationRequest(map, "check_authentication");

    // Check for sreg namespace
    if (resp.isVersion2()) {
      assertEquals(map.get("openid.ns.sreg"),
        SimpleRegistration.OPENID_SREG_NAMESPACE_11);
    }

    resp = carq.processUsing(serverInfo);
    assertTrue(resp.isVersion2());
    assertTrue(resp instanceof CheckAuthenticationResponse);
    CheckAuthenticationResponse carp = (CheckAuthenticationResponse) resp;
    assertTrue(carp.isValid());
  }
  String v2 = "http://specs.openid.net/auth/2.0";

  @Test
  public void testVersion2() throws Exception {
    String s = Utils.readFileAsString("test/data/2.txt");
    s += "openid.ns=" + v2;

    Request req = MessageFactory.parseRequest(s);
    assertTrue(req instanceof AssociationRequest);
    Response resp = req.processUsing(serverInfo);
    assertTrue(resp instanceof AssociationResponse);
    assertTrue(resp.isVersion2());

    s = resp.toUrlString();
    Response resp2 = MessageFactory.parseResponse(s);
    assertTrue(resp2.isVersion2());
    assertTrue(resp2 instanceof AssociationResponse);

    AssociationResponse ar = (AssociationResponse) resp2;

    assertTrue(ar.getSessionType(), "DH-SHA1".equals(ar.getSessionType()));
    assertTrue("HMAC-SHA1".equals(ar.getAssociationType()));
    assertTrue(defaultLifespan == ar.getExpiresIn());
    assertTrue(null == ar.getMacKey());
    assertTrue(null != ar.getEncryptedMacKey());
    assertTrue(null != ar.getDhServerPublic());
    assertTrue(null == ar.getErrorCode());
    assertTrue(v2.equals(ar.getNamespace()));
  }

  @Test
  public void test3version2() throws Exception {
    DiffieHellman dh = new DiffieHellman(p, g);
    AssociationResponse ar = associate(dh);

    assertTrue(ar.getSessionType(), "DH-SHA1".equals(ar.getSessionType()));
    assertTrue("HMAC-SHA1".equals(ar.getAssociationType()));
    assertTrue(defaultLifespan == ar.getExpiresIn());
    assertTrue(null == ar.getErrorCode());
    assertTrue(null == ar.getMacKey());

    byte[] encKey = ar.getEncryptedMacKey();
    assertTrue(null != encKey);

    BigInteger serverPublic = ar.getDhServerPublic();
    assertTrue(null != serverPublic);

    byte[] clearKey = dh.xorSecret(serverPublic, encKey);

    // authenticate
    String s = Utils.readFileAsString("test/data/3b.txt");
    s += "?openid.ns=" + v2 + "?openid.assoc_handle=" +
      URLEncoder.encode(ar.getAssociationHandle(), "UTF-8");

    Request req = MessageFactory.parseRequest(s);

    assertTrue(req instanceof AuthenticationRequest);
    assertTrue(req.isVersion2());
    assertTrue(((AuthenticationRequest) req).getClaimedIdentity() == null);
    Response resp = req.processUsing(serverInfo);

    assertTrue(resp instanceof AuthenticationResponse);
    assertTrue(resp.isVersion2());

    s = resp.toUrlString();

    Response resp2 = MessageFactory.parseResponse(s);
    assertTrue(resp2 instanceof AuthenticationResponse);
    assertTrue(resp2.isVersion2());
    AuthenticationResponse authr = (AuthenticationResponse) resp;

    String sigList = authr.getSignedList();
    assertTrue(sigList != null);
    assertTrue(sigList.indexOf("claimed_id") == -1);
    String signature = authr.getSignature();
    assertTrue(signature != null);
    String namespace = authr.getNamespace();
    assertTrue(v2.equals(namespace));

    String reSigned = authr.sign("HMAC-SHA1", clearKey, sigList);
    assertEquals(reSigned, signature);

    // check that we can authenticate the signaure
    Map<String,String> map = authr.toMap();
    CheckAuthenticationRequest carq = new CheckAuthenticationRequest(map, "check_authentication");

    resp = carq.processUsing(serverInfo);
    assertTrue(resp.isVersion2());
    assertTrue(resp instanceof CheckAuthenticationResponse);
    CheckAuthenticationResponse carp = (CheckAuthenticationResponse) resp;
    assertTrue(carp.isValid());
  }

  @Test
  public void test3version2_badsig() throws Exception {
    DiffieHellman dh = new DiffieHellman(p, g);
    AssociationResponse ar = associate(dh);

    assertTrue(ar.getSessionType(), "DH-SHA1".equals(ar.getSessionType()));
    assertTrue("HMAC-SHA1".equals(ar.getAssociationType()));
    assertTrue(defaultLifespan == ar.getExpiresIn());
    assertTrue(null == ar.getErrorCode());
    assertTrue(null == ar.getMacKey());

    byte[] encKey = ar.getEncryptedMacKey();
    assertTrue(null != encKey);

    BigInteger serverPublic = ar.getDhServerPublic();
    assertTrue(null != serverPublic);

    byte[] clearKey = dh.xorSecret(serverPublic, encKey);

    // authenticate
    String s = Utils.readFileAsString("test/data/3b.txt");
    s += "?openid.ns=" + v2 + "?openid.assoc_handle=" + URLEncoder.encode(ar.getAssociationHandle(), "UTF-8");

    Request req = MessageFactory.parseRequest(s);

    assertTrue(req instanceof AuthenticationRequest);
    assertTrue(req.isVersion2());
    assertTrue(((AuthenticationRequest) req).getClaimedIdentity() == null);
    Response resp = req.processUsing(serverInfo);

    assertTrue(resp instanceof AuthenticationResponse);
    assertTrue(resp.isVersion2());

    s = resp.toUrlString();

    Response resp2 = MessageFactory.parseResponse(s);
    assertTrue(resp2 instanceof AuthenticationResponse);
    assertTrue(resp2.isVersion2());
    AuthenticationResponse authr = (AuthenticationResponse) resp;
    assertTrue(null != authr.getUrlEndPoint());

    String sigList = authr.getSignedList();
    assertTrue(sigList != null);
    assertTrue(sigList.indexOf("claimed_id") == -1);
    String signature = authr.getSignature();
    assertTrue(signature != null);
    String namespace = authr.getNamespace();
    assertTrue(v2.equals(namespace));

    String reSigned = authr.sign("HMAC-SHA1", clearKey, sigList);
    assertEquals(reSigned, signature);

    // Check that the wrong signature doesn't authenticate
    Map<String,String> map = authr.toMap();
    map.put("openid.sig", "pO+52CAFEBABEuu0lVRivEeu2Zw=");
    CheckAuthenticationRequest carq = new CheckAuthenticationRequest(map, "check_authentication");
    assertTrue(carq.isVersion2());

    resp = carq.processUsing(serverInfo);
    assertTrue(resp instanceof CheckAuthenticationResponse);
    CheckAuthenticationResponse carp = (CheckAuthenticationResponse) resp;
    assertFalse(carp.isValid());
  }

  @Test
  public void test3_claimedid_noncecheck() throws Exception {
    DiffieHellman dh = new DiffieHellman(p, g);
    AssociationResponse ar = associate(dh);

    assertTrue(ar.getSessionType(), "DH-SHA1".equals(ar.getSessionType()));
    assertTrue("HMAC-SHA1".equals(ar.getAssociationType()));
    assertTrue(defaultLifespan == ar.getExpiresIn());
    assertTrue(null == ar.getErrorCode());
    assertTrue(null == ar.getMacKey());

    byte[] encKey = ar.getEncryptedMacKey();
    assertTrue(null != encKey);

    BigInteger serverPublic = ar.getDhServerPublic();
    assertTrue(null != serverPublic);

    byte[] clearKey = dh.xorSecret(serverPublic, encKey);

    // authenticate
    String s = Utils.readFileAsString("test/data/3c.txt");
    s += "?openid.ns=" + v2 + "?openid.assoc_handle=" + URLEncoder.encode(ar.getAssociationHandle(), "UTF-8");

    Request req = MessageFactory.parseRequest(s);

    assertTrue(req instanceof AuthenticationRequest);
    assertTrue(req.isVersion2());
    assertTrue(((AuthenticationRequest) req).getClaimedIdentity() != null);
    Response resp = req.processUsing(serverInfo);

    assertTrue(resp instanceof AuthenticationResponse);
    assertTrue(resp.isVersion2());

    s = resp.toUrlString();

    Response resp2 = MessageFactory.parseResponse(s);
    assertTrue(resp2 instanceof AuthenticationResponse);
    assertTrue(resp2.isVersion2());
    AuthenticationResponse authr = (AuthenticationResponse) resp;

    String sigList = authr.getSignedList();
    assertTrue(sigList != null);
    assertTrue(sigList.indexOf("claimed_id") != -1);
    String signature = authr.getSignature();
    assertTrue(signature != null);
    String namespace = authr.getNamespace();
    assertTrue(v2.equals(namespace));

    String reSigned = authr.sign("HMAC-SHA1", clearKey, sigList);
    assertEquals(reSigned, signature);

    // check that we can authenticate the signaure
    Map<String,String> map = authr.toMap();
    CheckAuthenticationRequest carq = new CheckAuthenticationRequest(map, "check_authentication");

    resp = carq.processUsing(serverInfo);
    assertTrue(resp.isVersion2());
    assertTrue(resp instanceof CheckAuthenticationResponse);
    CheckAuthenticationResponse carp = (CheckAuthenticationResponse) resp;
    assertTrue(carp.isValid());

    // A 2nd check auth should fail (nonce check)
    try {
      resp = carq.processUsing(serverInfo);
      assertTrue(false);
    } catch (OpenIdException e) {
      // should throw
    }
  }

  @Test
  public void testEndsWithEquals() throws Exception {
    StringBuilder s = new StringBuilder();
    s.append("openid.assoc_handle=%7BHMAC-SHA1%7D%7B44e56");
    s.append("f1d%7D%7BqrHn2Q%3D%3D%7D&openid.identity=http%3A%");
    s.append("2F%2Fmisja.pip.verisignlabs.com%2F&openid.mode=ch");
    s.append("eckid_setup");
    s.append("&openid.return_to=http%3A%2F%2Fradagast.biz%2Felg");
    s.append("g2%2Fmod%2Fopenid_client%2Freturn.php%3Fresponse_");
    s.append("nonce%3DR");
    s.append("qyqPiwW&openid.sreg.optional=email%2Cfullname");
    s.append("&openid.trust_root=");

    try {
      // no longer throws an exception because an unspecified
      // trust_root is assumed to be the return_to url
      Request req = MessageFactory.parseRequest(s.toString());
    } catch (OpenIdException unexpected) {
      assertTrue(false);
    }
  }

  @Test
  public void testEmptyIdentity() throws Exception {
    StringBuilder s = new StringBuilder();
    s.append("openid.return_to=http%3A%2F%2Ftest.vladlife.c");
    s.append("om%2Ffivestores%2Fclass.openid.php&openid.cancel_to");
    s.append("=&openid.mode=checkid_setup&openid.identity=&openid");
    s.append(".trust_root=http%3A%2F%2Ftest.vladlife.com&");
    try {
      Request req = MessageFactory.parseRequest(s.toString());
      Response resp = req.processUsing(serverInfo);
      assertTrue(false);
    } catch (OpenIdException expected) {
    }
  }

  @Test
  public void testMissingDhPublic() throws Exception {

    String s = "openid.mode=associate" + "&openid.session_type=DH-SHA1";

    try {
      Request req = MessageFactory.parseRequest(s);
      assertTrue(false);
    } catch (OpenIdException expected) {
    }
  }

  /** Tests that 'realm' is treated just like 'trust_root' */
  @Test
  public void testRealm() throws Exception {
    DiffieHellman dh = new DiffieHellman(p, g);
    AssociationResponse ar = associate(dh);
    StringBuilder s = new StringBuilder();
    s.append("openid.return_to=http%3A%2F%2Fexample.com&ope");
    s.append("nid.realm=http%3A%2F%2Fexample.com&openid.ns=http%");
    s.append("3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&openid.claimed_id");
    s.append("=http%3A%2F%2Falice.example.com&openid.mode=checkid");
    s.append("_setup&openid.identity=http%3A%2F%2Fexample.com&ope");
    s.append("nid.assoc_handle=");
    s.append(ar.getAssociationHandle());

    Request req = MessageFactory.parseRequest(s.toString());
    req.processUsing(serverInfo);
  }

  /** Tests that trailing slashes on URLs are *not* canonicalized.
   * That is: http://example.com is not equals to http://example.com/
   */
  @Test
  public void testTrailing() throws Exception {
    StringBuilder s = new StringBuilder();
    s.append("openid.return_to=http%3A%2F%2Fexample.com&ope");
    s.append("nid.realm=http%3A%2F%2Fexample.com/&openid.ns=http%");
    s.append("3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&openid.claimed_id");
    s.append("=http%3A%2F%2Falice.example.com&openid.mode=checkid");
    s.append("_setup&openid.identity=http%3A%2F%2Fexample.com&ope");
    s.append("nid.assoc_handle=1b184cb");

    try {
      Request req = MessageFactory.parseRequest(s.toString());
      req.processUsing(serverInfo);
      assertTrue(false);
    } catch (OpenIdException expected) {
    }
  }

  /** Tests that identity can change.
   */
  @Test
  public void testChangeId() throws Exception {
    StringBuilder s = new StringBuilder();
    s.append("openid.identity=http%3A%2F%2Fhans.beta.abtain.com%2F");
    s.append("&openid.mode=checkid_setup");
    s.append("&openid.return_to=http%3A%2F%2Fwww.schtuff.com%2F%3Faction%3Dope");
    s.append("nid_return%26dest%3D%26stay_logged_in%3DFalse%26response_no");
    s.append("nce%3D2006-12-");
    s.append("06T04%253A54%253A51ZQvGYW3");
    s.append("&openid.trust_root=http%3A%2F%2F%2A.schtuff.com%2F");
    s.append("&openid.assoc_handle=ahandle");

    Request req = MessageFactory.parseRequest(s.toString());
    assertTrue(req instanceof AuthenticationRequest);
    AuthenticationRequest ar = (AuthenticationRequest) req;
    assertFalse(ar.isIdentifierSelect());
    ar.setIdentity("http://newidentity.example.com");
    String x = ar.toUrlString();
    assertFalse(s.toString().equals(x));
  }

  /** Tests that identity_select works.
   */
  @Test
  public void testIdentitySelect() throws Exception {
    StringBuilder s = new StringBuilder();
    s.append("openid.identity=");
    s.append("http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select");
    s.append("&openid.mode=checkid_setup");
    s.append("&openid.return_to=http%3A%2F%2Fwww.schtuff.com%2F%3Faction%3Dope");
    s.append("nid_return%26dest%3D%26stay_logged_in%3DFalse%26response_no");
    s.append("nce%3D2006-12-");
    s.append("06T04%253A54%253A51ZQvGYW3");
    s.append("&openid.trust_root=http%3A%2F%2F%2A.schtuff.com%2F");
    s.append("&openid.assoc_handle=ahandle");

    Request req = MessageFactory.parseRequest(s.toString());
    assertTrue(req instanceof AuthenticationRequest);
    AuthenticationRequest ar = (AuthenticationRequest) req;
    assertTrue(ar.isIdentifierSelect());
  }

  /** Tests that extensions work.
   */
  @Test
  public void testExtensions() throws Exception {
    StringBuilder s = new StringBuilder();
    s.append("openid.identity=");
    s.append("http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select");
    s.append("&openid.mode=checkid_setup");
    s.append("&openid.return_to=http%3A%2F%2Fwww.schtuff.com%2F%3Faction%3Dope");
    s.append("nid_return%26dest%3D%26stay_logged_in%3DFalse%26response_no");
    s.append("nce%3D2006-12-");
    s.append("06T04%253A54%253A51ZQvGYW3");
    s.append("&openid.trust_root=http%3A%2F%2F%2A.schtuff.com%2F");
    s.append("&openid.assoc_handle=ahandle");
    s.append("&openid.ns.sig=http%3A%2F%2Fcommented.org");
    s.append("&openid.foo=happiness%20is%20a%20warm%20bun");
    s.append("&openid.glass.bunion=rocky%20sassoon%20gluebird%20foolia");

    try {
      MessageFactory.parseRequest(s.toString());
      assertTrue(false);
    } catch (OpenIdException e) {
      // expected: ns.sig cannot be redefined
    }
  }

  /** Tests that extensions work.
   */
  @Test
  public void testExtensions2() throws Exception {
    StringBuilder s = new StringBuilder();
    s.append("openid.identity=");
    s.append("http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select");
    s.append("&openid.mode=checkid_setup");
    s.append("&openid.return_to=http%3A%2F%2Fwww.schtuff.com%2F%3Faction%3Dope");
    s.append("nid_return%26dest%3D%26stay_logged_in%3DFalse%26response_no");
    s.append("nce%3D2006-12-");
    s.append("06T04%253A54%253A51ZQvGYW3");
    s.append("&openid.trust_root=http%3A%2F%2F%2A.schtuff.com%2F");
    s.append("&openid.ns.foo=http%3A%2F%2Fcommented.org");
    s.append("&openid.foo=trycke%20e%20for%20mycke");
    s.append("&openid.foo.bar=jaha%20vadda%20nu%20da");

    Request req = MessageFactory.parseRequest(s.toString());
    assertTrue(req instanceof AuthenticationRequest);
    AuthenticationRequest ar = (AuthenticationRequest) req;
    assertTrue(ar.isIdentifierSelect());

    Map map = ar.getExtensions();
    assertTrue(map.containsKey("ns.foo"));
    assertTrue(map.containsKey("foo"));
    assertTrue(map.containsKey("foo.bar"));
  }

  @Test
  public void testAssociateSHA256() throws Exception {
    StringBuilder s = new StringBuilder();
    s.append("openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0");
    s.append("&openid.session_type=DH-SHA256");
    s.append("&openid.assoc_type=HMAC-SHA256");
    s.append("&openid.mode=associate");
    s.append("&openid.dh_consumer_public=AJvqGzvFfjNk4LYWn8ZHSM7QyQnvxaaYUNwpSn089xdgBJx2okrYOWPesAl1%2B1oosnKPej6WBN9h2glimmv2g80h%2FAkDHLWU692efHdVhxnt4ZryI9SWAP0CIbznMs%2BphjGev4nS%2B5bLSR0lAbtvS7YQhiwfCJVrK5RrwplhZPzM");

    Request req = MessageFactory.parseRequest(s.toString());
    assertTrue(req instanceof AssociationRequest);
    AssociationRequest areq = (AssociationRequest) req;
    assertTrue(areq.isVersion2());

    // should not cause an exception in diffiehellman
    Response resp = req.processUsing(serverInfo);
    assertTrue(resp instanceof AssociationResponse);
    AssociationResponse aresp = (AssociationResponse) resp;
    assertTrue(aresp.isVersion2());
    System.out.println("assoc resp: " + aresp.toString());
  }

  @Test
  public void testAssociate20() throws Exception {
    StringBuilder s = new StringBuilder();
    s.append("openid.dh_consumer_public=GXmne0vGvF%2Fw9RHrk4McrUgxq3dmwURoKPhkrVdtBVNZtRlulFau2SBf%2FFT7JRo5LEcqY5CrctJlk%2B7YFcAyOX9VGd%2BmPfIE6cGPCTxy26USiJgjMEFPtkIRzT1y8lC7ypXvjZ5p0Q1hSg%2FuKdz1v0RAPICrVUrZ%2FgASGuqIpvQ%3D");
    s.append("&openid.assoc_type=HMAC-SHA1");
    s.append("&openid.session_type=DH-SHA1");
    s.append("&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0");
    s.append("&openid.mode=associate");

    Request req = MessageFactory.parseRequest(s.toString());
    assertTrue(req instanceof AssociationRequest);
    AssociationRequest areq = (AssociationRequest) req;
    assertTrue(areq.isVersion2());

    Response resp = req.processUsing(serverInfo);
    assertTrue(resp instanceof AssociationResponse);
    AssociationResponse aresp = (AssociationResponse) resp;
    assertTrue(aresp.isVersion2());

    // validate 2.0 association response
    Set<String> validParams = new HashSet<String>(Arrays.asList(new String[]{
              "assoc_handle",
              "assoc_type",
              "dh_server_public",
              "enc_mac_key",
              "expires_in",
              "mac_key",
              "ns",
              "session_type"}));
    String respStr = resp.toPostString();
    String[] respParamStrs = respStr.split("\n");
    for (int i = 0; i < respParamStrs.length; i++) {
      String name = respParamStrs[i].substring(0, respParamStrs[i].indexOf(":"));
      String value = respParamStrs[i].substring(respParamStrs[i].indexOf(":") + 1);
      assertTrue("'" + name + "' not a valid association response parameter",
        validParams.contains(name));
      if (name.equals("ns")) {
        assertTrue("Bad namespace: " + value,
          value.equals("http://specs.openid.net/auth/2.0"));
      }
    }
  }

  @Test
  public void testAssociate1x() throws Exception {
    StringBuilder s = new StringBuilder();
    s.append("openid.dh_consumer_public=GXmne0vGvF%2Fw9RHrk4McrUgxq3dmwURoKPhkrVdtBVNZtRlulFau2SBf%2FFT7JRo5LEcqY5CrctJlk%2B7YFcAyOX9VGd%2BmPfIE6cGPCTxy26USiJgjMEFPtkIRzT1y8lC7ypXvjZ5p0Q1hSg%2FuKdz1v0RAPICrVUrZ%2FgASGuqIpvQ%3D");
    s.append("&openid.assoc_type=HMAC-SHA1");
    s.append("&openid.session_type=DH-SHA1");
    s.append("&openid.mode=associate");

    Request req = MessageFactory.parseRequest(s.toString());
    assertTrue(req instanceof AssociationRequest);
    AssociationRequest areq = (AssociationRequest) req;
    assertFalse(areq.isVersion2());

    Response resp = req.processUsing(serverInfo);
    assertTrue(resp instanceof AssociationResponse);
    AssociationResponse aresp = (AssociationResponse) resp;
    assertFalse(aresp.isVersion2());

    // validate 1.1 association response
    Set<String> validParams = new HashSet<String>(Arrays.asList(new String[]{
              "assoc_handle",
              "assoc_type",
              "dh_server_public",
              "enc_mac_key",
              "expires_in",
              "mac_key",
              "session_type"}));
    String respStr = resp.toPostString();
    String[] respParamStrs = respStr.split("\n");
    for (int i = 0; i < respParamStrs.length; i++) {
      String[] tmp = respParamStrs[i].split(":");
      assertTrue("'" + tmp[0] + "' not a valid association response parameter",
        validParams.contains(tmp[0]));
    }
  }

  @Test
  public void testAuthenticate1xWithInvalidParam() throws Exception {
    // Some RPs have been using the post_grant parameter that was
    // eliminated in 2005; for 1.x requests we should just ignore
    // unrecognized parameters
    StringBuilder s = new StringBuilder();
    s.append("openid.identity=http%3A%2F%2Fhans.beta.abtain.com%2F");
    s.append("&openid.mode=checkid_setup");
    s.append("&openid.return_to=http%3A%2F%2Fwww.schtuff.com%2F%3Faction%3Dope");
    s.append("nid_return%26dest%3D%26stay_logged_in%3DFalse%26response_no");
    s.append("nce%3D2006-12-");
    s.append("06T04%253A54%253A51ZQvGYW3");
    s.append("&openid.trust_root=http%3A%2F%2F%2A.schtuff.com%2F");
    s.append("&openid.post_grant=return");
    try {
      Request req = MessageFactory.parseRequest(s.toString());
      assertTrue(req instanceof AuthenticationRequest);
    } catch (OpenIdException unexpected) {
      assertTrue("Should not throw an exception on unrecognized parameter", false);
    }
  }

  @Test
  public void testAuthenticate2xWithInvalidParam() throws Exception {
    StringBuilder s = new StringBuilder();
    s.append("openid.identity=");
    s.append("http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select");
    s.append("&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0");
    s.append("&openid.mode=checkid_setup");
    s.append("&openid.return_to=http%3A%2F%2Fwww.schtuff.com%2F%3Faction%3Dope");
    s.append("nid_return%26dest%3D%26stay_logged_in%3DFalse%26response_no");
    s.append("nce%3D2006-12-");
    s.append("06T04%253A54%253A51ZQvGYW3");
    s.append("&openid.trust_root=http%3A%2F%2F%2A.schtuff.com%2F");
    s.append("&openid.foo=trycke%20e%20for%20mycke");
    try {
      Request req = MessageFactory.parseRequest(s.toString());
      assertTrue("Should throw an exception on unrecognized parameter", false);
      assertTrue(req instanceof AuthenticationRequest);
    } catch (OpenIdException expected) {
    }
  }

  // Check that the trust_root/realm gets set to the return_to
  // parameter if it is unspecified
  @Test
  public void testAuthenticate2xDumbModeWithNoRealm() throws Exception {
    StringBuilder s = new StringBuilder();
    s.append("openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0");
    s.append("&openid.claimed_id=http%3A%2F%2Ffoo.pip.verisignlabs.com%2F");
    s.append("&openid.identity=http%3A%2F%2Ffoo.pip.verisignlabs.com%2F");
    s.append("&openid.return_to=http%3A%2F%2Fbar.com%2Fadmin%2FLogin");
    s.append("&openid.mode=checkid_setup");
    try {
      Request req = MessageFactory.parseRequest(s.toString());
      assertTrue(req instanceof AuthenticationRequest);
      AuthenticationRequest areq = (AuthenticationRequest) req;
      assertEquals("trust_root should be equal to return_to", areq.getTrustRoot(), "http://bar.com/admin/Login");
    } catch (OpenIdException unexpected) {
      assertTrue("Should not throw an exception, threw '" + unexpected.getMessage() + "'", false);
    }
  }

  // Make sure that check authentication responses follow the 1.1 spec
  @Test
  public void testSignatureValidation1xDumbMode() throws Exception {
    StringBuilder s = new StringBuilder();
    s.append("openid.identity=http%3A%2F%2Fidentity.bar.baz%2F");
    s.append("&openid.mode=checkid_setup");
    s.append("&openid.return_to=http%3A%2F%2Fwww.foo.bar%2F");
    try {
      // First get the stateless authentication request
      Request req = MessageFactory.parseRequest(s.toString());
      assertFalse(req.isVersion2());
      assertTrue(req instanceof AuthenticationRequest);
      AuthenticationRequest areq = (AuthenticationRequest) req;
      // Now construct the response
      Response resp = areq.processUsing(serverInfo);
      assertFalse(resp.isVersion2());
      assertTrue(resp instanceof AuthenticationResponse);
      AuthenticationResponse aresp = (AuthenticationResponse) resp;
      // Build the check authentication request from the auth response
      CheckAuthenticationRequest carq = new CheckAuthenticationRequest(aresp.toMap(), "check_authentication");
      assertFalse(carq.isVersion2());
      // Now get the check authentication response
      resp = carq.processUsing(serverInfo);
      assertFalse(resp.isVersion2());
      assertTrue(resp instanceof CheckAuthenticationResponse);
      CheckAuthenticationResponse carp = (CheckAuthenticationResponse) resp;
      assertTrue(carp.isValid());
      // Verify that the POST string for check auth response matches spec
      String respStr = carp.toPostString();
      System.out.println(respStr);
      Matcher m = Pattern.compile("^openid.mode:", Pattern.MULTILINE).matcher(respStr);
      assertTrue("Mode parameter 'openid.mode' must be in 1.x check auth responses", m.find());
      m = Pattern.compile("^is_valid:true$", Pattern.MULTILINE).matcher(respStr);
      assertTrue("Must have is_valid parameter in check auth response", m.find());
      m = Pattern.compile("^ns:", Pattern.MULTILINE).matcher(respStr);
      assertFalse("Must not have an ns parameter in 1.x check auth responses", m.find());
      // Parse the response string
      resp = MessageFactory.parseResponse(respStr);
      assertFalse(resp.isVersion2());
      assertTrue(resp instanceof CheckAuthenticationResponse);
    } catch (OpenIdException unexpected) {
      assertTrue("Should not throw an exception, threw '" + unexpected.getMessage() + "'", false);
    }
  }

  // Make sure that check authentication responses follow the 2.0 spec
  @Test
  public void testSignatureValidation2xDumbMode() throws Exception {
    StringBuilder s = new StringBuilder();
    s.append("openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select");
    s.append("&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0");
    s.append("&openid.mode=checkid_setup");
    s.append("&openid.return_to=http%3A%2F%2Fwww.foo.bar%2F");
    try {
      // First get the stateless authentication request
      Request req = MessageFactory.parseRequest(s.toString());
      assertTrue(req.isVersion2());
      assertTrue(req instanceof AuthenticationRequest);
      AuthenticationRequest areq = (AuthenticationRequest) req;
      // Now construct the response
      Response resp = areq.processUsing(serverInfo);
      assertTrue(resp.isVersion2());
      assertTrue(resp instanceof AuthenticationResponse);
      AuthenticationResponse aresp = (AuthenticationResponse) resp;
      // Build the check authentication request from the auth response
      CheckAuthenticationRequest carq = new CheckAuthenticationRequest(aresp.toMap(), "check_authentication");
      assertTrue(carq.isVersion2());
      // Now get the check authentication response
      resp = carq.processUsing(serverInfo);
      assertTrue(resp.isVersion2());
      assertTrue(resp instanceof CheckAuthenticationResponse);
      CheckAuthenticationResponse carp = (CheckAuthenticationResponse) resp;
      assertTrue(carp.isValid());
      // Verify that the POST string for check auth response matches spec
      String respStr = carp.toPostString();
      Matcher m = Pattern.compile("^(mode|openid.mode):", Pattern.MULTILINE).matcher(respStr);
      assertTrue("No mode value allowed in 2.x check auth responses", !m.find());
      m = Pattern.compile("^is_valid:true$", Pattern.MULTILINE).matcher(respStr);
      assertTrue("Must have is_valid parameter in check auth response", m.find());
      m = Pattern.compile("^ns:", Pattern.MULTILINE).matcher(respStr);
      assertTrue("Must have an ns parameter in 2.x check auth responses", m.find());
      // Parse the response string
      resp = MessageFactory.parseResponse(respStr);
      assertTrue(resp.isVersion2());
      assertTrue(resp instanceof CheckAuthenticationResponse);
    } catch (OpenIdException unexpected) {
      assertTrue("Should not throw an exception, threw '" + unexpected.getMessage() + "'", false);
    }
  }

 void validatePapeRequest(PapeRequest pr) throws Exception {
    assertTrue(pr.isValid());
    assertNotNull(pr.getMaxAuthAge());
    assertEquals(pr.getMaxAuthAge().intValue(), 3600);
    Collection<String> policies = pr.getPreferredAuthPolicies();
    HashSet<String> pSet = new HashSet<String>();
    pSet.add("http://schemas.openid.net/pape/policies/2007/06/phishing-resistant");
    pSet.add("http://schemas.openid.net/pape/policies/2007/06/multi-factor");
    pSet.add("http://schemas.openid.net/pape/policies/2007/06/multi-factor-physical");
    int i = 0;
    for (String pStr : policies) {
      i++;
      if (pSet.contains(pStr)) {
        break;
      }
    }
    assertTrue(i < pSet.size());
  }

  @Test
  public void testPapeRequestFromQuery() throws Exception {
    StringBuilder s = new StringBuilder();
    s.append("openid.identity=");
    s.append("http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select");
    s.append("&openid.mode=checkid_setup");
    s.append("&openid.return_to=http%3A%2F%2Fwww.schtuff.com%2F%3Faction%3Dope");
    s.append("nid_return%26dest%3D%26stay_logged_in%3DFalse%26response_no");
    s.append("nce%3D2006-12-");
    s.append("06T04%253A54%253A51ZQvGYW3");
    s.append("&openid.trust_root=http%3A%2F%2F%2A.schtuff.com%2F");
    s.append("&openid.ns.foo=http%3A%2F%2Fspecs.openid.net%2Fextensions%2Fpape%2F1.0");
    s.append("&openid.foo.max_auth_age=3600");
    s.append("&openid.foo.preferred_auth_policies=");
    s.append("http%3A%2F%2Fschemas.openid.net%2Fpape%2Fpolicies%2F2007%2F06%2F");
    s.append("phishing-resistant+http%3A%2F%2Fschemas.openid.net");
    s.append("%2Fpape%2Fpolicies%2F2007%2F06%2Fmulti-factor+");
    s.append("http%3A%2F%2Fschemas.openid.net%2Fpape%2Fpolicies%2F2007%2F06%2F");
    s.append("multi-factor-physical");

    Request req = MessageFactory.parseRequest(s.toString());
    assertTrue(req instanceof AuthenticationRequest);
    AuthenticationRequest ar = (AuthenticationRequest) req;
    assertTrue(ar.isIdentifierSelect());

    PapeRequest pr = new PapeRequest(ar.getExtensions());
    System.out.println(pr.toString());
    validatePapeRequest(pr);
    assertEquals(pr.getPreferredAuthPolicies().size(), 3);
  }

  @Test
  public void testPapeRequestWithEmptyAuthPoliciesFromQuery() throws Exception {
    StringBuilder s = new StringBuilder();
    s.append("openid.identity=");
    s.append("http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select");
    s.append("&openid.mode=checkid_setup");
    s.append("&openid.return_to=http%3A%2F%2Fwww.schtuff.com%2F%3Faction%3Dope");
    s.append("nid_return%26dest%3D%26stay_logged_in%3DFalse%26response_nonce%3D2006-12-06T04%253A54%253A51ZQvGYW3");
    s.append("&openid.trust_root=http%3A%2F%2F%2A.schtuff.com%2F");
    s.append("&openid.ns.foo=http%3A%2F%2Fspecs.openid.net%2Fextensions%2Fpape%2F1.0");
    s.append("&openid.foo.max_auth_age=3600");
    s.append("&openid.foo.preferred_auth_policies=");

    Request req = MessageFactory.parseRequest(s.toString());
    assertTrue(req instanceof AuthenticationRequest);
    AuthenticationRequest ar = (AuthenticationRequest) req;
    assertTrue(ar.isIdentifierSelect());

    PapeRequest pr = new PapeRequest(ar.getExtensions());
    System.out.println(pr.toString());
    validatePapeRequest(pr);
    assertEquals(pr.getPreferredAuthPolicies().size(), 0);
  }

  @Test
  public void testPapeRequestGenerate() throws Exception {
    String identity = "http://specs.openid.net/auth/2.0/identifier_select";
    String returnTo = "http://www.schtuff.com/?action=openid_return&dest=&stay_logged_in=False&response_nonce=2006-12-06t04%3A54%3A51ZQvGYW3";
    String trustRoot = "http://*.schtuff.com/";
    String assocHandle = "ahandle";
    AuthenticationRequest ar = AuthenticationRequest.create(identity,
            returnTo,
            trustRoot,
            assocHandle);
    assertTrue(ar.isIdentifierSelect());
    PapeRequest pr = new PapeRequest();
    pr.setMaxAuthAge(3600);
    pr.setPreferredAuthPolicies(new String[]{"http://schemas.openid.net/pape/policies/2007/06/phishing-resistant",
              "http://schemas.openid.net/pape/policies/2007/06/multi-factor",
              "http://schemas.openid.net/pape/policies/2007/06/multi-factor-physical"});
    ar.addExtension(pr);
    PapeRequest pr1 = new PapeRequest(ar.getExtensions());
    validatePapeRequest(pr1);

    String s = ar.toUrlString();
    Request req = MessageFactory.parseRequest(s);
    assertTrue(req instanceof AuthenticationRequest);
    AuthenticationRequest ar2 = (AuthenticationRequest) req;
    assertTrue(ar2.isIdentifierSelect());

    PapeRequest pr2 = new PapeRequest(ar2.getExtensions());
    System.out.println(pr2.toString());
    validatePapeRequest(pr2);
  }

 void validatePapeResponse(PapeResponse pr) throws Exception {
    assertTrue(pr.isValid());
    assertNotNull(pr.getAuthTime());
    assertEquals(pr.getAuthTime().getTime(), 1196510400000L);
    Collection policies = pr.getAuthPolicies();
    assertEquals(policies.size(), 3);
    String[] pArray = {"http://schemas.openid.net/pape/policies/2007/06/phishing-resistant",
      "http://schemas.openid.net/pape/policies/2007/06/multi-factor",
      "http://schemas.openid.net/pape/policies/2007/06/multi-factor-physical"};
    Iterator it = policies.iterator();
    while (it.hasNext()) {
      String pStr = (String) it.next();
      int i = 0;
      for (i = 0; i < pArray.length; i++) {
        if (pStr.equals(pArray[i])) {
          break;
        }
      }
      assertTrue(i < pArray.length);
    }
    assertNotNull(pr.getNistAuthLevel());
    assertEquals(pr.getNistAuthLevel().intValue(), 4);
  }

  @Test
  public void testPapeResponseFromQuery() throws Exception {
    StringBuilder s = new StringBuilder();
    s.append("openid.op_endpoint=http%3A%2F%2Fexample.com");
    s.append("&openid.pape.auth_policies=http%3A%2F%2Fschemas.openid.net");
    s.append("%2Fpape%2Fpolicies%2F2007%2F06%2Fphishing-resistant+");
    s.append("http%3A%2F%2Fschemas.openid.net%2Fpape%2Fpolicies%2F2007%2F06%2F");
    s.append("multi-factor+http%3A%2F%2Fschemas.openid.net%2Fpape%2Fpolicies");
    s.append("%2F2007%2F06%2Fmulti-factor-physical");
    s.append("&openid.pape.auth_time=2007-12-01T12%3A00%3A00Z");
    s.append("&openid.return_to=http%3A%2F%2Fwww.schtuff.com%2F%3Faction%3D");
    s.append("openid_return%26dest%3D%26stay_logged_in%3DFalse%26");
    s.append("response_nonce%3D2006-12-06t04%253A54%253A51ZQvGYW3");
    s.append("&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0");
    s.append("&openid.response_nonce=2007-10-15T17%3A38%3A16ZZvI%3D");
    s.append("&openid.pape.nist_auth_level=4");
    s.append("&openid.assoc_handle=694d5d70-7b45-11dc-8e68-bbf7f7e8a280");
    s.append("&openid.signed=assoc_handle%2Cidentity%2Cresponse_nonce%2Creturn_to%2Cclaimed_id%2Cop_endpoint");
    s.append("&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select");
    s.append("&openid.ns.pape=http%3A%2F%2Fspecs.openid.net%2Fextensions%2Fpape%2F1.0");
    s.append("&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select");
    s.append("&openid.mode=id_res");
    s.append("&openid.invalidate_handle=ahandle");
    s.append("&openid.sig=iqoAqcoyYK3XX9%2BOdxmdjUYLUJs%3D");

    Response resp = MessageFactory.parseResponse(s.toString());
    assertTrue(resp instanceof AuthenticationResponse);
    AuthenticationResponse ar = (AuthenticationResponse) resp;
    assertTrue(ar.isVersion2());

    PapeResponse pr = new PapeResponse(ar.getExtensions());
    System.out.println(pr.toString());
    validatePapeResponse(pr);
  }

  @Test
  public void testPapeResponseGenerate() throws Exception {
    String identity = "http://specs.openid.net/auth/2.0/identifier_select";
    String returnTo = "http://www.schtuff.com/?action=openid_return&dest=&stay_logged_in=False&response_nonce=2006-12-06t04%3A54%3A51ZQvGYW3";
    String trustRoot = "http://*.schtuff.com/";
    String assocHandle = "ahandle";
    AuthenticationRequest request = AuthenticationRequest.create(identity,
            returnTo,
            trustRoot,
            assocHandle);
    Response resp = request.processUsing(serverInfo);
    assertTrue(resp instanceof AuthenticationResponse);
    assertTrue(resp.isVersion2());
    AuthenticationResponse ar = (AuthenticationResponse) resp;
    PapeResponse pr = new PapeResponse();
    pr.setAuthTime(new Date(1196510400000L));
    assertTrue(pr.getParam("auth_policies").equals("none"));
    pr.setAuthPolicies(new String[]{});
    assertTrue(pr.getParam("auth_policies").equals("none"));
    pr.setAuthPolicies(new String[]{"http://schemas.openid.net/pape/policies/2007/06/phishing-resistant",
              "http://schemas.openid.net/pape/policies/2007/06/multi-factor",
              "http://schemas.openid.net/pape/policies/2007/06/multi-factor-physical"});
    pr.setNistAuthLevel(4);
    ar.addExtension(pr);
    System.out.println(ar.toUrlString());
    String[] signed = ar.getSignedList().split(",");
    Set<String> signSet = new HashSet<String>();
    signSet.addAll(Arrays.asList(signed));
    assertTrue(signSet.contains("ns.pape"));
    assertTrue(signSet.contains("pape.auth_policies"));
    assertTrue(signSet.contains("pape.auth_time"));
    assertTrue(signSet.contains("pape.nist_auth_level"));

    PapeResponse pr1 = new PapeResponse(ar.getExtensions());
    validatePapeResponse(pr1);

    String s = ar.toUrlString();
    System.out.println(s);
    Response req = MessageFactory.parseResponse(s);
    assertTrue(req instanceof AuthenticationResponse);
    AuthenticationResponse ar2 = (AuthenticationResponse) req;
    assertTrue(ar2.isVersion2());

    PapeResponse pr2 = new PapeResponse(ar2.getExtensions());
    System.out.println(pr2.toString());
    validatePapeResponse(pr2);
  }

  /*
   * Some RPs (*cough* blogger *cough*) have been known to use the
   * (invalid) http://openid.net/sreg/1.0 namespace for sreg in 2.0
   * requests.  If this happens we should return the same namespace
   * for interoperability reasons.
   */
  @Test
  @SuppressWarnings("unchecked")
  public void testSreg10() throws Exception {
    StringBuilder s = new StringBuilder();
    s.append("openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0");
    s.append("&openid.claimed_id=http%3A%2F%2Fhans.pip.verisignlabs.com%2F");
    s.append("&openid.identity=http%3A%2F%2Fhans.pip.verisignlabs.com%2F");
    s.append("&openid.return_to=https%3A%2F%2Fwww.blogger.com%2Fcomment.do%3FloginRedirect%3Dlm6phc1udus9");
    s.append("&openid.realm=https%3A%2F%2Fwww.blogger.com");
    s.append("&openid.mode=checkid_setup");
    s.append("&openid.ns.sreg=http%3A%2F%2Fopenid.net%2Fsreg%2F1.0");
    s.append("&openid.sreg.optional=nickname%2Cfullname");

    Request req = MessageFactory.parseRequest(s.toString());
    assertTrue(req instanceof AuthenticationRequest);
    AuthenticationRequest areq = (AuthenticationRequest) req;

    SimpleRegistration sreg = areq.getSimpleRegistration();
    assertTrue(sreg.isRequested());
    Map<String,String> supplied = new HashMap<String,String>();
    for (String x : sreg.getOptional()) {
      supplied.put(x, "blahblah");
    }
    sreg = new SimpleRegistration(Collections.EMPTY_SET, sreg.getOptional(),
      supplied, "", sreg.getNamespace());
    areq.setSimpleRegistration(sreg);

    Response resp = req.processUsing(serverInfo);
    assertTrue(resp instanceof AuthenticationResponse);
    AuthenticationResponse aresp = (AuthenticationResponse) resp;
    assertTrue(aresp.isVersion2());

    Map<String,String> map = aresp.toMap();
    // Check for sreg namespace
    if (resp.isVersion2()) {
      assertEquals(map.get("openid.ns.sreg"), SimpleRegistration.OPENID_SREG_NAMESPACE_10);
    }
  }

  /*
   * Check that normal sreg ns works
   */
  @Test
  @SuppressWarnings("unchecked")
  public void testSreg11() throws Exception {
    StringBuilder s = new StringBuilder();
    s.append("openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0");
    s.append("&openid.claimed_id=http%3A%2F%2Fhans.pip.verisignlabs.com%2F");
    s.append("&openid.identity=http%3A%2F%2Fhans.pip.verisignlabs.com%2F");
    s.append("&openid.return_to=https%3A%2F%2Fwww.blogger.com%2Fcomment.do%3FloginRedirect%3Dlm6phc1udus9");
    s.append("&openid.realm=https%3A%2F%2Fwww.blogger.com");
    s.append("&openid.mode=checkid_setup");
    s.append("&openid.ns.sreg=http%3A%2F%2Fopenid.net%2Fextensions%2Fsreg%2F1.1");
    s.append("&openid.sreg.optional=nickname%2Cfullname");

    Request req = MessageFactory.parseRequest(s.toString());
    assertTrue(req instanceof AuthenticationRequest);
    AuthenticationRequest areq = (AuthenticationRequest) req;

    SimpleRegistration sreg = areq.getSimpleRegistration();
    assertTrue(sreg.isRequested());
    Map<String,String> supplied = new HashMap<String,String>();
    for (String x : sreg.getOptional()) {
      supplied.put(x, "blahblah");
    }
    sreg = new SimpleRegistration(Collections.EMPTY_SET, sreg.getOptional(), supplied, "", sreg.getNamespace());
    areq.setSimpleRegistration(sreg);

    Response resp = req.processUsing(serverInfo);
    assertTrue(resp instanceof AuthenticationResponse);
    AuthenticationResponse aresp = (AuthenticationResponse) resp;
    assertTrue(aresp.isVersion2());

    Map map = aresp.toMap();
    // Check for sreg namespace
    if (resp.isVersion2()) {
      assertEquals((String) map.get("openid.ns.sreg"),
              SimpleRegistration.OPENID_SREG_NAMESPACE_11);
    }
  }

  /*
   * Any bad sreg ns gets converted to the proper
   * http://openid.net/extensions/sreg/1.1
   */
  @Test
  @SuppressWarnings("unchecked")
  public void testSregBadNS() throws Exception {
    StringBuilder s = new StringBuilder();
    s.append("openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0");
    s.append("&openid.claimed_id=http%3A%2F%2Fhans.pip.verisignlabs.com%2F");
    s.append("&openid.identity=http%3A%2F%2Fhans.pip.verisignlabs.com%2F");
    s.append("&openid.return_to=https%3A%2F%2Fwww.blogger.com%2Fcomment.do%3FloginRedirect%3Dlm6phc1udus9");
    s.append("&openid.realm=https%3A%2F%2Fwww.blogger.com");
    s.append("&openid.mode=checkid_setup");
    s.append("&openid.ns.sreg=http%3A%2F%2Fopenid.net%2Fextensions%2Fsreg%2Ffoo");
    s.append("&openid.sreg.optional=nickname%2Cfullname");

    Request req = MessageFactory.parseRequest(s.toString());
    assertTrue(req instanceof AuthenticationRequest);
    AuthenticationRequest areq = (AuthenticationRequest) req;

    SimpleRegistration sreg = areq.getSimpleRegistration();
    assertTrue(sreg.isRequested());
    Map<String,String> supplied = new HashMap<String,String>();
    for (String x : sreg.getOptional()) {
      supplied.put(x, "blahblah");
    }
    sreg = new SimpleRegistration(Collections.EMPTY_SET, sreg.getOptional(),
      supplied, "", sreg.getNamespace());
    areq.setSimpleRegistration(sreg);

    Response resp = req.processUsing(serverInfo);
    assertTrue(resp instanceof AuthenticationResponse);
    AuthenticationResponse aresp = (AuthenticationResponse) resp;
    assertTrue(aresp.isVersion2());

    Map map = aresp.toMap();
    // Check for sreg namespace
    if (resp.isVersion2()) {
      assertEquals((String) map.get("openid.ns.sreg"), SimpleRegistration.OPENID_SREG_NAMESPACE_11);
    }
  }
/* // This test is not likely to pass as the underlying Map (HashMap) is not
   // guaranteed to preserve ordering of keys/values.
  @Test
  public void testMessageMapToUrlStringOk() throws Exception {
    Map<String,String> testMap = new LinkedHashMap<String,String>();
    testMap.put(CheckAuthenticationRequest.OPENID_ASSOC_HANDLE, "adfasdf");
    testMap.put("openid.mode", "check_authentication");
    testMap.put(AuthenticationResponse.OPENID_IDENTITY, "http://foo");
    testMap.put(AuthenticationResponse.OPENID_RETURN_TO, "http://bar");
    testMap.put(AuthenticationResponse.OPENID_NONCE, "42");
    testMap.put(AuthenticationResponse.OPENID_SIG, "siggy");

    CheckAuthenticationRequest testMessage = new CheckAuthenticationRequest(testMap, "check_authentication");
    String urlStr = testMessage.toUrlString();
    System.out.println("urlstr:\'" + urlStr + "'");
    String compareStr = "openid.assoc_handle=adfasdf&openid.identity=http%3A%2F%2Ffoo&openid.return_to=http%3A%2F%2Fbar&openid.sig=siggy&openid.mode=check_authentication&openid.response_nonce=42";
    //                   openid.sig=siggy&openid.identity=http%3A%2F%2Ffoo&openid.response_nonce=42&openid.mode=check_authentication&openid.assoc_handle=adfasdf&openid.return_to=http%3A%2F%2Fbar
    assertTrue(compareStr.equals(urlStr));
  }
*/
  @Test
  public void testMessageMapToUrlStringNullParam() throws Exception {
    Map<String,String> testMap = new HashMap<String,String>();
    testMap.put(CheckAuthenticationRequest.OPENID_ASSOC_HANDLE, "adfasdf");
    testMap.put("openid.mode", "check_authentication");
    testMap.put(AuthenticationResponse.OPENID_IDENTITY, "http://foo");
    testMap.put(AuthenticationResponse.OPENID_RETURN_TO, "http://bar");
    testMap.put(AuthenticationResponse.OPENID_NONCE, null);
    testMap.put(AuthenticationResponse.OPENID_SIG, "siggy");

    boolean caught = false;
    try {
      CheckAuthenticationRequest testMessage = new CheckAuthenticationRequest(testMap, "check_authentication");
      testMessage.toUrlString();
    } catch (OpenIdException e) {
      caught = true;
    }
    assertTrue(caught);
  }

  @Test
  public void testCheckAuthNonceOk() throws Exception {
    // first establish association
    StringBuilder s = new StringBuilder();
    s.append("openid.dh_consumer_public=GXmne0vGvF%2Fw9RHrk4McrUgxq3dmwURoKPhkrVdtBVNZtRlulFau2SBf%2FFT7JRo5LEcqY5CrctJlk%2B7YFcAyOX9VGd%2BmPfIE6cGPCTxy26USiJgjMEFPtkIRzT1y8lC7ypXvjZ5p0Q1hSg%2FuKdz1v0RAPICrVUrZ%2FgASGuqIpvQ%3D");
    s.append("&openid.assoc_type=HMAC-SHA1");
    s.append("&openid.session_type=DH-SHA1");
    s.append("&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0");
    s.append("&openid.mode=associate");

    Request req = MessageFactory.parseRequest(s.toString());
    assertTrue(req instanceof AssociationRequest);
    AssociationRequest areq = (AssociationRequest) req;
    assertTrue(areq.isVersion2());

    Response resp = req.processUsing(serverInfo);
    assertTrue(resp instanceof AssociationResponse);
    AssociationResponse aresp = (AssociationResponse) resp;
    assertTrue(aresp.isVersion2());

    // now do an auth req
    StringBuilder areqStr = new StringBuilder();
    areqStr.append("openid.identity=");
    areqStr.append("http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select");
    areqStr.append("&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0");
    areqStr.append("&openid.mode=checkid_setup");
    areqStr.append("&openid.return_to=http%3A%2F%2Fwww.schtuff.com%2F%3Faction%3Dope");
    areqStr.append("nid_return%26dest%3D%26stay_logged_in%3DFalse%26response_no");
    areqStr.append("nce%3D2006-12-06T04%253A54%253A51ZQvGYW3");
    areqStr.append("&openid.trust_root=http%3A%2F%2F%2A.schtuff.com%2F");
    areqStr.append("&openid.assoc_handle=");
    areqStr.append(aresp.getAssociationHandle());
    req = MessageFactory.parseRequest(areqStr.toString());
    assertTrue(req instanceof AuthenticationRequest);
    resp = req.processUsing(serverInfo);
    assertTrue(resp instanceof AuthenticationResponse);
    AuthenticationResponse authResp = (AuthenticationResponse) resp;
    String nonce = authResp.getNonce();

    // and check the response
    CheckAuthenticationRequest checkReq = new CheckAuthenticationRequest(authResp.toMap(), "check_authentication");
    resp = checkReq.processUsing(serverInfo);

    // do it again, using same assoc handle
    req = MessageFactory.parseRequest(areqStr.toString());
    assertTrue(req instanceof AuthenticationRequest);
    resp = req.processUsing(serverInfo);
    assertTrue(resp instanceof AuthenticationResponse);
    authResp = (AuthenticationResponse) resp;
    // make sure we didn't get the same nonce
    assertFalse(nonce.equals(authResp.getNonce()));

    // and check the 2nd response
    // since we didn't get the same nonce in the 2nd response we
    // shouldn't receive an exception claiming this is the case
    checkReq = new CheckAuthenticationRequest(authResp.toMap(), "check_authentication");
    resp = checkReq.processUsing(serverInfo);
  }

  @Test
  public void testCheckAuthNonceDuplicate() throws Exception {
    // first establish association
    StringBuilder s = new StringBuilder();
    s.append("openid.dh_consumer_public=GXmne0vGvF%2Fw9RHrk4McrUgxq3dmwURoKPhkrVdtBVNZtRlulFau2SBf%2FFT7JRo5LEcqY5CrctJlk%2B7YFcAyOX9VGd%2BmPfIE6cGPCTxy26USiJgjMEFPtkIRzT1y8lC7ypXvjZ5p0Q1hSg%2FuKdz1v0RAPICrVUrZ%2FgASGuqIpvQ%3D");
    s.append("&openid.assoc_type=HMAC-SHA1");
    s.append("&openid.session_type=DH-SHA1");
    s.append("&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0");
    s.append("&openid.mode=associate");

    Request req = MessageFactory.parseRequest(s.toString());
    assertTrue(req instanceof AssociationRequest);
    AssociationRequest areq = (AssociationRequest) req;
    assertTrue(areq.isVersion2());

    Response resp = req.processUsing(serverInfo);
    assertTrue(resp instanceof AssociationResponse);
    AssociationResponse aresp = (AssociationResponse) resp;
    assertTrue(aresp.isVersion2());

    // now do an auth req
    StringBuilder areqStr = new StringBuilder();
    areqStr.append("openid.identity=");
    areqStr.append("http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select");
    areqStr.append("&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0");
    areqStr.append("&openid.mode=checkid_setup");
    areqStr.append("&openid.return_to=http%3A%2F%2Fwww.schtuff.com%2F%3Faction%3Dope");
    areqStr.append("nid_return%26dest%3D%26stay_logged_in%3DFalse%26response_no");
    areqStr.append("nce%3D2006-12-06T04%253A54%253A51ZQvGYW3");
    areqStr.append("&openid.trust_root=http%3A%2F%2F%2A.schtuff.com%2F");
    areqStr.append("&openid.assoc_handle=");
    areqStr.append(aresp.getAssociationHandle());
    req = MessageFactory.parseRequest(areqStr.toString());
    assertTrue(req instanceof AuthenticationRequest);
    resp = req.processUsing(serverInfo);
    assertTrue(resp instanceof AuthenticationResponse);
    AuthenticationResponse authResp = (AuthenticationResponse) resp;
    authResp.getNonce();

    // and check the response
    CheckAuthenticationRequest checkReq =
      new CheckAuthenticationRequest(authResp.toMap(), "check_authentication");
    checkReq.processUsing(serverInfo);

    // now try checking it again, using the same response
    // should get an exception indicating nonce reuse
    boolean caught = false;
    try {
      checkReq = new CheckAuthenticationRequest(authResp.toMap(), "check_authentication");
      checkReq.processUsing(serverInfo);
    } catch (OpenIdException e) {
      caught = true;
    }
    assertTrue(caught);
  }
}
