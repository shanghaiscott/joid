/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.swdouglass.joid;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.util.Map;
import java.util.Set;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.PostMethod;

/**
 *
 * @author scott
 */
public class MessageFactory {

  public static String OPENID_MODE = "openid.mode";
  public static String ASSOCIATE_MODE = "associate";
  public static String CHECKID_IMMEDIATE_MODE = "checkid_immediate";
  public static String CHECKID_SETUP_MODE = "checkid_setup";
  public static String CHECK_AUTHENTICATION_MODE = "check_authentication";

  /**
   * Parses a query into a response.
   *
   * @param query the query to parse.
   * @return the parsed response.
   * @throws OpenIdException if the query cannot be parsed into a known
   *  response.
   */
  public static Response parseResponse(String query) throws OpenIdException {
    Map<String, String> map;
    try {
      if (MessageParser.numberOfNewlines(query) == 1) {
        map = MessageParser.urlEncodedToMap(query);
      } else {
        map = MessageParser.postedToMap(query);
      }
    } catch (IOException e) {
      throw new OpenIdException("Error parsing " + query + ": " + e.toString());
    }

    Set set = map.keySet();
    if ((set.contains(AssociationResponse.OPENID_SESSION_TYPE) &&
      set.contains(AssociationResponse.OPENID_ENC_MAC_KEY)) ||
      set.contains(AssociationResponse.OPENID_ASSOCIATION_TYPE)) {
      return new AssociationResponse(map);
    } else if (set.contains(AuthenticationResponse.OPENID_SIG)) {
      return new AuthenticationResponse(map);
    } else if (set.contains(CheckAuthenticationResponse.OPENID_IS_VALID)) {
      return new CheckAuthenticationResponse(map);
    } else {
      throw new OpenIdException("Cannot parse response from " + query);
    }
  }

  /**
   * Parses a query into a request.
   *
   * @param query the query to parse.
   * @return the parsed request.
   * @throws OpenIdException if the query cannot be parsed into a known
   *  request.
   */
  public static Request parseRequest(String query)
    throws UnsupportedEncodingException, OpenIdException {
    Map<String, String> map;
    try {
      map = parseQuery(query);
    } catch (UnsupportedEncodingException e) {
      throw new OpenIdException("Error parsing " + query + ": " + e.toString());
    }

    String s = map.get(OPENID_MODE);
    if (ASSOCIATE_MODE.equals(s)) {
      return new AssociationRequest(map, s);
    } else if (CHECKID_IMMEDIATE_MODE.equals(s) || CHECKID_SETUP_MODE.equals(s)) {
      return new AuthenticationRequest(map, s);
    } else if (CHECK_AUTHENTICATION_MODE.equals(s)) {
      return new CheckAuthenticationRequest(map, s);
    } else {
      throw new OpenIdException("Cannot parse request from " + query);
    }
  }

  /**
   * Parses a query into a map.
   *
   * @param query the query to parse.
   * @return the parsed request.
   * @throws UnsupportedEncodingException if the string is not properly
   *  UTF-8 encoded.
   */
  public static Map<String, String> parseQuery(String query)
    throws UnsupportedEncodingException {
    return MessageParser.urlEncodedToMap(query);
  }

  public static Response send(Request req, String dest)
    throws IOException, OpenIdException {
    StringBuilder b = new StringBuilder();

    BufferedReader in = null;
    try {

      // Previously, HttpURLConnection was used here.
      // There was a bug reported with consuming LiveJournal OpenIDs:
      // http://groups.google.com/group/joid-dev/browse_thread/thread/962cf46501ea660d?pli=1
      // A patch was posted which never made it into the code. The patch
      // (of which a modified version is below) uses HttpClient, which is already
      // used by the Discover class. However, it probably would have worked
      // as originally written if we called HttpURLConnection.setRequestMethod("POST").
      // TODO: Elminate HttpClient if possible, replace with HttpURLConnection.
      // TODO: Some networks proxy all outbound HTTP, need to allow setup of a proxy server.
      HttpClient client = new HttpClient();
      PostMethod post = new PostMethod(dest);

      for (Map.Entry param : req.toMap().entrySet()) {
        String key = (String) param.getKey();
        String value = (String) param.getValue();
        post.addParameter(key, value);
      }

      client.executeMethod(post);

      in = new BufferedReader(new InputStreamReader(
        post.getResponseBodyAsStream()));

      String str;
      int lines = 0;
      while ((str = in.readLine()) != null) {
        b.append(str);
        b.append('\n');
        lines += 1;
      }
      if (lines == 1) {
        // query string
        b.deleteCharAt(b.length() - 1);
      }
    } finally {
      if (in != null) {
        in.close();
      }
    }
    return parseResponse(b.toString());
  }
}
