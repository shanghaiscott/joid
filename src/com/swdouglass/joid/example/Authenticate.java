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
 */
package com.swdouglass.joid.example;

import com.swdouglass.joid.AuthenticationRequest;
import com.swdouglass.joid.AuthenticationResponse;
import com.swdouglass.joid.Crypto;
import com.swdouglass.joid.DiffieHellman;
import com.swdouglass.joid.MessageFactory;
import com.swdouglass.joid.OpenIdException;
import com.swdouglass.joid.Response;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Properties;

/**
 * Example on how to authenticate
 */
public class Authenticate {

  public static void main(String[] argv) throws Exception {
    String id = "http://alice.example.com";
    String returnTo = "http://localhost:8084/joid_swd/echo";
    String trustRoot = "http://localhost:8084";
    String fileName = argv[0];

    new Authenticate(id, returnTo, trustRoot, fileName);
  }

  public Authenticate(String identity, String returnTo,
    String trustRoot, String fileName)
    throws IOException, OpenIdException, NoSuchAlgorithmException {
    Properties p = new Properties();
    File f = new File(fileName);
    p.load(new FileInputStream(f));

    String handle = p.getProperty("handle");
    String dest = p.getProperty("_dest");

    AuthenticationRequest ar = AuthenticationRequest.create(identity, returnTo,
      trustRoot,
      handle);

    Response response = MessageFactory.send(ar, dest);
    System.out.println("Response=" + response + "\n");

    AuthenticationResponse authr = (AuthenticationResponse) response;

    BigInteger privKey = Crypto.convertToBigIntegerFromString(p.getProperty(
      "privateKey"));
    BigInteger modulus = Crypto.convertToBigIntegerFromString(p.getProperty(
      "modulus"));
    BigInteger serverPublic = Crypto.convertToBigIntegerFromString(p.getProperty(
      "publicKey"));
    byte[] encryptedKey = Crypto.convertToBytes(p.getProperty("encryptedKey"));

    DiffieHellman dh = DiffieHellman.recreate(privKey, modulus);
    Crypto crypto = new Crypto();
    crypto.setDiffieHellman(dh);
    byte[] clearKey = crypto.decryptSecret(serverPublic, encryptedKey);

    String signature = authr.getSignature();
    System.out.println("Server's signature: " + signature);

    String sigList = authr.getSignedList();
    String reSigned = authr.sign("HMAC-SHA1", clearKey, sigList);
    System.out.println("Our signature:      " + reSigned);

  }
}
