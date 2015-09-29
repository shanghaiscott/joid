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
package com.swdouglass.joid.consumer;

import com.swdouglass.joid.OpenIdException;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.methods.GetMethod;
import org.xml.sax.SAXException;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.w3c.dom.Node;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import javax.xml.parsers.DocumentBuilder;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.NamedNodeMap;

public class Discoverer {

  private static Log log = LogFactory.getLog(Discoverer.class);

  public ServerAndDelegate findIdServer(String identityUrl)
    throws Exception {
    ServerAndDelegate serverAndDelegate = new ServerAndDelegate();
    debug("identityUrl=" + identityUrl);

    // FIXME: What about XRI? 7.3.1
    // OpenID 2.0, 7.3.2 Discovery: we first try to check with YADIS protocol
    if (!findWithYadis(identityUrl, serverAndDelegate)) {
      // Then we parse some HTML 7.3.3
      if (!findWithHTML(identityUrl, serverAndDelegate)) {
        throw new OpenIdException("No openid.server found on identity page.");
      }
    }

    return serverAndDelegate;
  }

  public Boolean findWithYadis(String identityUrl, ServerAndDelegate serverAndDelegate)
    throws Exception {
    boolean found = false;

    GetMethod get = new GetMethod(identityUrl);
    httpGet(get);
    Header contentType = get.getResponseHeader("Content-Type");
    if (contentType != null && contentType.getValue().contains("application/xrds+xml")) {
      // then we're looking at the xrds service doc already
      XRDSDocument xrdsDocument = buildXrdsDocument(get);
      handleXrdsDocument(serverAndDelegate, xrdsDocument);
      found = true;
    } else {
      Header locationHeader = get.getResponseHeader("X-XRDS-Location");
      if (locationHeader != null) {
        // then we go to this URL
        get.releaseConnection();
        debug("found yadis header: " + locationHeader.getValue());
        XRDSDocument xrdsDocument = fetchYadisDocument(locationHeader.getValue());
        handleXrdsDocument(serverAndDelegate, xrdsDocument);
        found = true;
      }
    }

    return found;
  }

  /**
   * 14.2.1.  Relying Parties
   */
  public Boolean findWithHTML(String identityUrl, ServerAndDelegate serverAndDelegate)
    throws Exception {
    boolean found = false;

    GetMethod get = new GetMethod(identityUrl);

    BufferedReader in = httpGet(get);

    String str;
    while ((str = in.readLine()) != null) {
      if (serverAndDelegate.getServer() == null) {
        serverAndDelegate.setServer(findLinkTag(str, "openid.server", in));
      }
      if (serverAndDelegate.getDelegate() == null) {
        serverAndDelegate.setDelegate(findLinkTag(str, "openid.delegate", in));
      }
      if (str.indexOf("</head>") >= 0) {
        break;
      }
    }
    if (serverAndDelegate.getServer() != null) {
      found = true;
    }

    return found;
  }

  private BufferedReader httpGet(GetMethod get) throws IOException {
    HttpClient httpClient = new HttpClient();
    httpClient.getParams().setSoTimeout(15000);
    httpClient.getParams().setConnectionManagerTimeout(15000);
    int status = httpClient.executeMethod(get);
    debug("status=" + status);
    dumpHeaders(get.getResponseHeaders());
    return (new BufferedReader(new InputStreamReader(get.getResponseBodyAsStream())));
  }

  private void handleXrdsDocument(ServerAndDelegate serverAndDelegate,
    XRDSDocument xrdsDocument) {
    List<XRDSService> services = xrdsDocument.getServiceList();
    for (XRDSService service : services) {
      debug("service=" + service.getUri());
      serverAndDelegate.setServer(service.getUri());
      serverAndDelegate.setDelegate(service.getOpenIDDelegate());
    }
  }

  private void dumpHeaders(Header[] responseHeaders) {
    for (Header responseHeader : responseHeaders) {
      debug(responseHeader.getName() + "=" + responseHeader.getValue());
    }
  }

  private XRDSDocument fetchYadisDocument(String location)
    throws IOException, ParserConfigurationException, SAXException {
    GetMethod get = new GetMethod(location);
    httpGet(get);
    XRDSDocument doc = buildXrdsDocument(get);
    return doc;
  }

  private XRDSDocument buildXrdsDocument(GetMethod get)
    throws ParserConfigurationException, SAXException, IOException {
    XRDSDocument doc = new XRDSDocument();
    DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
    DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
    Document document = docBuilder.parse(get.getResponseBodyAsStream());
    get.releaseConnection();
    NodeList list = document.getElementsByTagName("Service");
    for (int i = 0; i < list.getLength(); i++) {
      Node node = list.item(i);
      //<Service priority="30" xmlns:openid="http://openid.net/xmlns/1.0">
		  //  <Type>http://openid.net/signon/1.0</Type>
		  //  <URI>http://www.livejournal.com/openid/server.bml</URI>
		  //  <openid:Delegate>http://www.livejournal.com/users/frank/</openid:Delegate>
	    //</Service>

      debug(nodeToString(node));// the Node.toString() isn't showing what we want
      NodeList childNodes = node.getChildNodes();
      XRDSService service = new XRDSService();
      Set<String> types = new LinkedHashSet<String>();
      for (int j = 0; j < childNodes.getLength(); j++) {
        //http://yadis.org/wiki/Yadis_1.0_(HTML)#7._The_Yadis_document    
        Node node2 = childNodes.item(j);
        if (! node2.getNodeName().equals("#text")) {
          debug(node2.getNodeName() + ": " + node2.getTextContent());
        }
        if (node2.getNodeName().equalsIgnoreCase("URI")) {
          service.setUri(node2.getTextContent());
        } else if (node2.getNodeName().equalsIgnoreCase("openid:Delegate")) {
          service.setOpenIDDelegate(node2.getTextContent());
        } else if (node2.getNodeName().equalsIgnoreCase("type")) {
          types.add(node2.getTextContent());
          if (! "http://openid.net/signon/1.0".equalsIgnoreCase(node2.getTextContent())) {
            log.warn("XRDS service type is NOT http://openid.net/signon/1.0");
            // TODO: throw an exception? do I care?
            //http://openid.net/srv/ax/1.0
            //http://specs.openid.net/auth/2.0/server
          }
          service.setType(types);
        }
      }
      doc.addService(service);
    }
    debug(doc.toString());
    return doc;
  }

  private String findLinkTag(String str, String rel, BufferedReader in)
    throws IOException {
    int index = str.indexOf(rel);
    if (index != -1) {
      // TODO: ensure it's a proper link tag
      // TODO: allow reverse ordering
      // TODO: link tags can have more than one href!!! handle that?
      String href = findHref(str, index);
      if (href == null) {
        // no href found, check next line
        str = in.readLine();
        if (str != null) {
          href = findHref(str, 0);
        }
      }
      return href;
    }
    return null;
  }

  private String findHref(String str, int index) {
    String href = null;
    int indexOfHref = str.indexOf("href=", index);
    if (indexOfHref != -1) {
      href = str.substring(indexOfHref + 6, str.indexOf("\"", indexOfHref + 8));
    }
    return href;
  }

  private void debug(String message) {
    if (log.isDebugEnabled()) {
      log.debug(message);
    }
  }

  private String nodeToString(Node inNode) {
    StringBuilder sb = new StringBuilder();
    sb.append("[Node: name=");
    sb.append(inNode.getNodeName());
    if (inNode.hasAttributes()) {
      sb.append(", attributes={");
      NamedNodeMap nnmap = inNode.getAttributes();
      for (int i = 0; i < nnmap.getLength(); i++) {
        sb.append (nnmap.item(i).getNodeName());
        sb.append("=");
        sb.append(nnmap.item(i).getNodeValue());
        sb.append(" ");
      }
    }
    sb.append("}]");
    return sb.toString();
  }
}
