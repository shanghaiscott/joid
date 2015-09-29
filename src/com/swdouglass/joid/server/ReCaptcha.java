/*
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
 */
package com.swdouglass.joid.server;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Implements support for the
 * <a href="http://recaptcha.net/apidocs/captcha/">reCAPTCHA</a> system
 * for identifying human computer operators.
 * 
 * @author scott
 */
public class ReCaptcha {

  private static final Log log = LogFactory.getLog(ReCaptcha.class);
  private static final String VERIFY_URL = "http://api-verify.recaptcha.net/verify";
  public static final String PARAM_RECAPTCHA_CHALLENGE = "recaptcha_challenge_field";
  public static final String PARAM_RECAPTCHA_RESPONSE = "recaptcha_response_field";
  public static final String PARAM_RECAPTCHA_ERROR = "error";

  /**
   * This method posts the four parameters necessary to solve a
   * <a href="http://recaptcha.net/apidocs/captcha/">captcha</a>.
   * 
   * @param privateKey Your recaptcha private key
   * @param remoteAddr The IP address of the end user
   * @param challenge The mangled text displayed
   * @param response Then end-user's interpretation of that text
   * @return null if successful, error message if not
   */
  public static String check(String privateKey, String remoteAddr,
    String challenge, String response) {
    String message = null;
    String str = null;
    if (challenge == null || response == null) {
      message = "Challenge and response strings can't be null!";
    } else {
      try {

        HttpClient client = new HttpClient();
        PostMethod post = new PostMethod(VERIFY_URL);
        post.addParameter("privatekey", privateKey);
        post.addParameter("remoteip", remoteAddr);
        post.addParameter("challenge", challenge);
        post.addParameter("response", response);
        client.executeMethod(post);
        BufferedReader in = new BufferedReader(new InputStreamReader(post.
          getResponseBodyAsStream()));
        str = in.readLine(); // read the first line of the response
        if (str == null) {
          message = "Null read from server."; // treat this as not verfied
        } else {
          boolean valid = "true".equals(str);
          if (!valid) {
            str = in.readLine(); // get next line which has message
            if (str.length() > 1) {
              message = str;
            } else {
              message = "missing error message?";
            }
          }
        }

      } catch (IOException ex) {
        log.error(ex);
        ex.printStackTrace();
      }
    }
    if (log.isDebugEnabled()) {
      log.debug("Response: " + str);
    }
    return message;
  }
}
