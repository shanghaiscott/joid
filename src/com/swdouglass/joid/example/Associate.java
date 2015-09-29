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

import com.swdouglass.joid.AssociationRequest;
import com.swdouglass.joid.AssociationResponse;
import com.swdouglass.joid.Crypto;
import com.swdouglass.joid.DiffieHellman;
import com.swdouglass.joid.MessageFactory;
import com.swdouglass.joid.OpenIdException;
import com.swdouglass.joid.Response;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Properties;

/**
 * Example on how to associate.
 */
public class Associate {

  public static void main(String[] argv) throws Exception {
    String dest = "http://localhost:8084/joid_swd/server";
    new Associate(dest, argv[0]);
  }

  public Associate(String destination, String fileName)
          throws IOException, OpenIdException {
    DiffieHellman dh = DiffieHellman.getDefault();
    Crypto crypto = new Crypto();
    crypto.setDiffieHellman(dh);

    AssociationRequest ar = AssociationRequest.create(crypto);

    Response response = MessageFactory.send(ar, destination);
    System.out.println("Response=" + response + "\n");

    AssociationResponse asr = (AssociationResponse) response;

    Properties props = new Properties();
    props.setProperty("handle", asr.getAssociationHandle());
    props.setProperty("publicKey",
            Crypto.convertToString(asr.getDhServerPublic()));
    props.setProperty("encryptedKey",
            Crypto.convertToString(asr.getEncryptedMacKey()));

    BigInteger privateKey = dh.getPrivateKey();
    props.setProperty("privateKey", Crypto.convertToString(privateKey));
    props.setProperty("modulus",
            Crypto.convertToString(DiffieHellman.DEFAULT_MODULUS));

    props.setProperty("_dest", destination);

    File f = new File(fileName);
    props.store(new FileOutputStream(f), "Association result");
    System.out.println("Results written into " + f.getCanonicalPath());

  /*
  Crypto crypto = new Crypto();
  dh = DiffieHellman.recreate(privateKey, p);
  crypto.setDiffieHellman(dh);
  byte[] clearKey	= crypto.decryptSecret(asr.getDhServerPublic(),
  asr.getEncryptedMacKey());
  System.out.println("Clear key: "+Crypto.convertToString(clearKey));
   */
  }
}
