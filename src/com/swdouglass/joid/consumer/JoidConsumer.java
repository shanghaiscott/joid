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

package com.swdouglass.joid.consumer;

import com.swdouglass.joid.AssociationRequest;
import com.swdouglass.joid.AssociationResponse;
import com.swdouglass.joid.AuthenticationRequest;
import com.swdouglass.joid.AuthenticationResponse;
import com.swdouglass.joid.CheckAuthenticationRequest;
import com.swdouglass.joid.CheckAuthenticationResponse;
import com.swdouglass.joid.Crypto;
import com.swdouglass.joid.DiffieHellman;
import com.swdouglass.joid.MessageFactory;
import com.swdouglass.joid.OpenIdException;
import com.swdouglass.joid.Response;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.logging.Log;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * This is the main class for consumers to use.
 * <p/>
 * It performs the following operations given an OpenID user identifier.
 * - Finds the OpenId Server
 * - Associates with the server if it hasn't done so already or if the
 * association has expired
 * - Provides url to the server an application to redirect to.
 * <p/>
 * ... some time later ...
 * <p/>
 * - Takes a request from an OpenId server after user has authenticated
 * - Verifies server signature and our signatures match to authenticate
 * - Returns the user's identifier if ok
 * <p/>
 * <p/>
 */
public class JoidConsumer {

  private static Log log = LogFactory.getLog(JoidConsumer.class);
  private Map<String, Properties> propSingleton;
  private Map<String, String> handleToIdServer;
  private Discoverer discoverer = new Discoverer();

  public JoidConsumer() {
    log.info("Constructor: JoidConsumer");
  }

  private synchronized Properties getProps(String idserver) {
    // TODO: just store the AssociationResponse instead of converting to props
    if (propSingleton == null) {
      propSingleton = new HashMap<String,Properties>();
      handleToIdServer = new HashMap<String,String>();
    }
    Properties props = propSingleton.get(idserver);
    if (props == null) { // TODO: also check expires_in time to make sure it's still valid
      try {
        props = associate(idserver);
        propSingleton.put(idserver, props);
        handleToIdServer.put(props.getProperty("handle"), idserver);
      } catch (Exception e) {
        e.printStackTrace();
      }
    }
    return props;
  }

  private Properties getPropsByHandle(String associationHandle)
  throws OpenIdException {
    String idServer = handleToIdServer.get(associationHandle);
    log.info("got idserver for handle: " + associationHandle + " - " + idServer);
    if (idServer == null) {
      throw new OpenIdException("handle for server not found!");
    }
    return getProps(idServer);
  }

  /**
   * To associate with an openid server
   *
   * @param idserver server url
   * @return
   * @throws java.io.IOException
   * @throws org.verisign.joid.OpenIdException
   *
   */
  public Properties associate(String idserver)
  throws IOException, OpenIdException {
    DiffieHellman dh = DiffieHellman.getDefault();
    Crypto crypto = new Crypto();
    crypto.setDiffieHellman(dh);

    AssociationRequest ar = AssociationRequest.create(crypto);

    log.info("[JoidConsumer] Attempting to associate with: " + idserver);
    log.info("Request=" + ar);

    Response response = MessageFactory.send(ar, idserver);
    log.info("Response=" + response + "\n");

    AssociationResponse asr = (AssociationResponse) response;

    Properties props = new Properties();
    props.setProperty("idServer", idserver);
    props.setProperty("handle", asr.getAssociationHandle());
    props.setProperty("publicKey",  Crypto.convertToString(asr.getDhServerPublic()));
    props.setProperty("encryptedKey", Crypto.convertToString(asr.getEncryptedMacKey()));

    BigInteger privateKey = dh.getPrivateKey();
    props.setProperty("privateKey", Crypto.convertToString(privateKey));
    props.setProperty("modulus", Crypto.convertToString(DiffieHellman.DEFAULT_MODULUS));

    props.setProperty("_dest", idserver);
    props.setProperty("expiresIn", "" + asr.getExpiresIn());

    /*
    Crypto crypto = new Crypto();
    dh = DiffieHellman.recreate(privateKey, p);
    crypto.setDiffieHellman(dh);
    byte[] clearKey	= crypto.decryptSecret(asr.getDhServerPublic(),
    asr.getEncryptedMacKey());
    System.out.println("Clear key: "+Crypto.convertToString(clearKey));
     */
    return props;
  }

  /**
   * <p>
   * This method is used by a relying party to create the url to redirect a
   * user to after entering their OpenId URL in a form.
   * </p>
   * <p>
   * It will find the id server found at the OpenID url, associate with the
   * server if necessary and return an authentication request url.
   * </p>
   *
   * @param identity  users OpenID url
   * @param returnTo  the url to return to after user is finished with OpenId provider
   * @param trustRoot base url that the authentication should apply to
   * @return
   * @throws OpenIdException
   */
  public String getAuthUrl(String identity, String returnTo, String trustRoot)
  throws OpenIdException {

    // find id server
    ServerAndDelegate idserver = null;
    try {
      idserver = discoverer.findIdServer(identity);
    } catch (Exception e) {
      e.printStackTrace();
      throw new OpenIdException("Could not get OpenId server from identifier.", e);
    }

    Properties p = getProps(idserver.getServer());
    String handle = p.getProperty("handle");

    // TODO: use delegate here, replace identity?

    AuthenticationRequest ar = AuthenticationRequest.create(identity, returnTo,
      trustRoot, handle);

    debug("urlString=" + ar.toUrlString());

    return idserver.getServer() + "?" + ar.toUrlString();
  }

  /**
   * This method will attempt to authenticate against the OpenID server.
   *
   * @param map
   * @return openid.identity if authentication was successful, null if unsuccessful
   * @throws IOException
   * @throws OpenIdException
   * @throws NoSuchAlgorithmException
   */
  public AuthenticationResult authenticate(Map<String,String> map)
  throws IOException, OpenIdException, NoSuchAlgorithmException {

    debug("request map in authenticate: " + map);
    AuthenticationResponse response = new AuthenticationResponse(map);
    // TODO: store nonce's to ensure we never accept the same value again - see sec 11.3 of spec 2.0
    Properties props;
    if (response.getInvalidateHandle() != null) {
      // then we have to send a authentication_request (dumb mode) to verify the signature
      CheckAuthenticationRequest checkReq =
        new CheckAuthenticationRequest(response.toMap(),
          MessageFactory.CHECK_AUTHENTICATION_MODE);
      props = getPropsByHandle(response.getInvalidateHandle());
      CheckAuthenticationResponse response2 =
        (CheckAuthenticationResponse) MessageFactory.send(checkReq, props.getProperty("idServer"));
      // This doesn't actually work, because for a check authentication response, the only
      // field returned is openid.is_valid!
      /*if (! response.getInvalidateHandle().equals(response2.getInvalidateHandle())) {
        throw new AuthenticationException("The invalidate_handles do not match, identity denied: "
          + response.getInvalidateHandle() + " != " + response2.getInvalidateHandle());
      }*/
      removeInvalidHandle(response.getInvalidateHandle());
      if (response2.isValid()) {
        // then this is a valid request, lets send it back
        return new AuthenticationResult(response.getIdentity(), response);
      } else {
        throw new AuthenticationException("Signature invalid, identity denied.");
      }
    } else {
      // normal properties
      props = getPropsByHandle(response.getAssociationHandle());

      // TODO: before returning a valid response, ensure return_to is a suburl of trust_root

      BigInteger privKey = Crypto.convertToBigIntegerFromString(props.getProperty("privateKey"));
      BigInteger modulus = Crypto.convertToBigIntegerFromString(props.getProperty("modulus"));
      BigInteger serverPublic = Crypto.convertToBigIntegerFromString(props.getProperty("publicKey"));
      byte[] encryptedKey = Crypto.convertToBytes(props.getProperty("encryptedKey"));

      /* String sig = response.sign(response.getAssociationType(),
      a.getMacKey(), response.getSignedList());
      isValid = sig.equals(response.getSignature());
       */
      DiffieHellman dh = DiffieHellman.recreate(privKey, modulus);
      Crypto crypto = new Crypto();
      crypto.setDiffieHellman(dh);
      byte[] clearKey = crypto.decryptSecret(serverPublic, encryptedKey);

      String signature = response.getSignature();
      debug("Server's signature: " + signature);

      String sigList = response.getSignedList();
      String reSigned = response.sign(clearKey, sigList);
      debug("Our signature:      " + reSigned);
      String identity = response.getIdentity();
      if (!signature.equals(reSigned)) {
        throw new AuthenticationException("OpenID signatures do not match! " +
          "claimed identity: " + identity);
      }
      debug("Signatures match, identity is ok: " + identity);
      return new AuthenticationResult(identity, response);
    }

  }

  /**
   * If openid.invalidate_handle was received, this will remove it from our
   * cache so it won't be used again.
   *
   * @param invalidateHandle
   */
  private void removeInvalidHandle(String invalidateHandle) {
    String idServer = handleToIdServer.remove(invalidateHandle);
    if (idServer != null) {
      propSingleton.remove(idServer);
    }
  }

  private void debug(String message) {
    if (log.isDebugEnabled()) {
      log.debug(message);
    }
  }
}
