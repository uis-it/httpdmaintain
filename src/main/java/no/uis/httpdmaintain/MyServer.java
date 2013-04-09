/*
 Copyright 2012-2013 University of Stavanger, Norway
 
 Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */

package no.uis.httpdmaintain;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringWriter;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.CharBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

/**
 * HTTP/HTTPS Server.
 */
@SuppressWarnings("restriction")
public class MyServer implements HttpHandler {

  private static final String SLASH = "/";
  private static final String SUN_X509 = "SunX509";
  private static final String LOCALHOST = "localhost";
  private static final int REQUEST_READ_BUFFER_SIZE = 300;
  private static final int HTTPS_DEFAULT_PORT = 444;
  private static final int HTTP_DEFAULT_PORT = 81;
  private static final int HTTP_OK = 200;
  private static final java.util.logging.Logger LOG = Logger.getLogger(MyServer.class.getName());

  private File messageFile;
  private String stopCmd;
  private String stopResponse;

  private MyServer(String stopCmd) {
    this.stopCmd = SLASH + stopCmd;
    this.stopResponse = "OK";
  }
  
  public static void main(String[] args) {
    try {
      int argIdx = 0;
      String cmd = readArg(args, argIdx++, null);
      String stopCmd = readArg(args, argIdx++, null);
      int port = readIntArg(args, argIdx++, HTTP_DEFAULT_PORT);
      int sport = readIntArg(args, argIdx++, HTTPS_DEFAULT_PORT);
      String keystoreFile = readArg(args, argIdx++, new File(System.getProperty("user.home"), "keystore.jks").getAbsolutePath());
      String keystorePasswd = readArg(args, argIdx++, "changeit");
      String fileName = readArg(args, argIdx++, "maintenance.html");

      if ("start".equals(cmd)) {
        new MyServer(stopCmd).startServer(port, sport, fileName, keystoreFile, keystorePasswd);
        return;
      } else if ("stop".equals(cmd)) {
        new MyServer(stopCmd).stopServer(port);
        return;
      }
    } catch(IOException | GeneralSecurityException e) {
      LOG.log(Level.SEVERE, "Starting Server", e);
    }
    showUsage();
  }

  private static String readArg(String[] args, int index, String defaultValue) {
    if (index < args.length) {
      return args[index];
    } else if (defaultValue != null) {
      return defaultValue;
    }
    throw new IllegalArgumentException();
  }

  private static int readIntArg(String[] args, int index, int defaultValue) {
    String arg = readArg(args, index, "");
    if (arg.length() == 0) {
      return defaultValue;
    }
    return Integer.valueOf(arg);
  }

  private static void showUsage() {
    System.out.println("Usage:");
    System.out.print("<cmd(start|stop)> ");
    System.out.print("<stopCmd> [port(8080)] ");
    System.out.print("[secure-port(8443)] [keystore(user.home/keystore.jks)] [keystorepassword(changeit)] ");
    System.out.println("[html(maintenance.html)]");
  }

  private void stopServer(int port) throws IOException {
    URL url = new URL("http", LOCALHOST, port, this.stopCmd);
    Object content = url.getContent();
    if (content instanceof InputStream) {

      int stopResponseLength = this.stopResponse.length();
      byte[] responseBuff = new byte[stopResponseLength + 1];
      int read = ((InputStream)content).read(responseBuff);
      if (read == stopResponseLength) {

        String response = new String(responseBuff, 0, read);
        if (response.equals(this.stopResponse)) {
          return;
        }
      }
    }
    throw new IllegalStateException();
  }

  private void startServer(int port, int sport, String msgFile, String keystoreFile, String keystorePasswd) throws IOException,
      GeneralSecurityException
  {
    File file = new File(msgFile);
    if (file.canRead()) {
      this.messageFile = file;
    } else {
      throw new IllegalArgumentException("File " + msgFile + " does not exist");
    }
    startHttpServer(port);

    startHttpsServer(sport, keystoreFile, keystorePasswd);

    LOG.info("Server started");
  }

  /**
   * With help from http://stackoverflow.com/questions/2308479/simple-java-https-server.
   * 
   * @param sport
   * @param keystoreFile
   * @param keystorePasswd
   * @throws GeneralSecurityException
   * @throws Exception
   */
  private void startHttpsServer(final int sport, String keystoreFile, String keystorePasswd) throws IOException,
      GeneralSecurityException
  {
    SSLContext sslContext = SSLContext.getInstance("TLS");

    KeyStore ks = KeyStore.getInstance("JKS");
    try (FileInputStream ksStream = new FileInputStream(keystoreFile)) {
      ks.load(ksStream, keystorePasswd.toCharArray());
    }

    KeyManagerFactory kmf = KeyManagerFactory.getInstance(SUN_X509);
    kmf.init(ks, keystorePasswd.toCharArray());

    TrustManagerFactory tmf = TrustManagerFactory.getInstance(SUN_X509);
    tmf.init(ks);

    sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

    HttpsServer sserver = HttpsServer.create(new InetSocketAddress(sport), 0);
    sserver.setHttpsConfigurator(new HttpsConfigurator(sslContext) {

      @Override
      public void configure(HttpsParameters params) {
        try {
          SSLContext c = SSLContext.getDefault();
          SSLEngine engine = c.createSSLEngine(LOCALHOST, sport);
          params.setNeedClientAuth(false);
          params.setCipherSuites(engine.getEnabledCipherSuites());
          params.setProtocols(engine.getEnabledProtocols());

          SSLParameters defaultSSLParams = c.getDefaultSSLParameters();
          params.setSSLParameters(defaultSSLParams);

        } catch(GeneralSecurityException ex) {
          LOG.log(Level.SEVERE, "startHttpsServe", ex);
        }
      }

    });

    sserver.createContext(SLASH, this);
    sserver.setExecutor(null);
    sserver.start();
  }

  public void startHttpServer(int port) throws IOException {
    LOG.info("Starting server");
    HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
    server.createContext(SLASH, this);
    server.setExecutor(null);
    server.start();
  }

  @Override
  public void handle(HttpExchange httpEx) throws IOException {
    if (receivedStop(httpEx)) {
      LOG.info("Received Stop Request");
      sendMessage(httpEx, "text/plain", this.stopResponse);
      httpEx.getHttpContext().getServer().stop(0);
    } else {
      LOG.info("Received request from " + httpEx.getRemoteAddress().toString());

      try (FileReader fr = new FileReader(this.messageFile)) {
        StringWriter sw = new StringWriter();
        CharBuffer cb = CharBuffer.allocate(REQUEST_READ_BUFFER_SIZE);
        int nboRead = 0;
        while ((nboRead = fr.read(cb)) > 0) {
          String s = cb.clear().toString();
          sw.append(s, 0, nboRead);
        }
        String result = sw.toString();
        sendMessage(httpEx, "text/html", result);
      }
    }
  }

  private void sendMessage(HttpExchange httpEx, String contentType, String response) throws IOException {
    httpEx.getResponseHeaders().add("Content-Type", contentType);
    httpEx.sendResponseHeaders(HTTP_OK, response.length());

    OutputStream os = httpEx.getResponseBody();
    os.write(response.getBytes());
    os.close();
  }

  private boolean receivedStop(HttpExchange httpEx) throws IOException {
    if ("GET".equals(httpEx.getRequestMethod()) && httpEx.getRequestURI().toString().equals(this.stopCmd)) {
      return true;
    }
    return false;
  }
}
