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

@SuppressWarnings("restriction")
public class MyServer implements HttpHandler {

  private File messageFile;
  private String stopCmd;
  private static java.util.logging.Logger log = Logger.getLogger(MyServer.class.getName());
  private String stopResponse;

  public static void main(String[] args) {
    try {
      int argIdx = 0;
      String cmd = readArg(args, argIdx++, null);
      String stopCmd = readArg(args, argIdx++, null);
      int port = readIntArg(args, argIdx++, 81);
      int sport = readIntArg(args, argIdx++, 444);
      String keystoreFile = readArg(args, argIdx++, new File(System.getProperty("user.home"), "keystore.jks").getAbsolutePath());
      String keystorePasswd = readArg(args, argIdx++, "changeit"); 
      String fileName = readArg(args, argIdx++, "maintenance.html");
      
      if (cmd.equals("start")) {
        new MyServer(stopCmd).startServer(port, sport, fileName, keystoreFile, keystorePasswd);
        return;
      } else if (cmd.equals("stop")) {
        new MyServer(stopCmd).stopServer(port);
        return;
      }
    } catch(Exception e) {
      log.log(Level.SEVERE, "Starting Server", e);
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
    //JOptionPane.showMessageDialog(null, "Usage:\n<cmd(start|stop)> <stopCmd> [port(8080)] [secure-port(8443)] [keystore(user.home/keystore.jks)] [keystorepassword(changeit)] [html(maintenance.html)]");
    System.out.println("Usage:\n<cmd(start|stop)> <stopCmd> [port(8080)] [secure-port(8443)] [keystore(user.home/keystore.jks)] [keystorepassword(changeit)] [html(maintenance.html)]");
  }

  private MyServer(String stopCmd) {
    this.stopCmd = "/" + stopCmd;
    stopResponse = "OK";
  }
  
  private void stopServer(int port) throws IOException {
    URL url = new URL("http", "localhost", port, this.stopCmd);
    Object content = url.getContent();
    if (content instanceof InputStream) {
      
      int stopResponseLength = stopResponse.length();
      byte[] responseBuff = new byte[stopResponseLength+1];
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
  
  private void startServer(int port, int sport, String msgFile, String keystoreFile, String keystorePasswd) throws Exception {
    File file = new File(msgFile);
    if (file.canRead()) {
      messageFile = file;
    } else {
      throw new IllegalArgumentException("File " + msgFile + " does not exist");
    }
    startHttpServer(port);
    
    startHttpsServer(sport, keystoreFile, keystorePasswd);
    
    log.info("Server started");
  }

  /**
   * With help from http://stackoverflow.com/questions/2308479/simple-java-https-server
   * 
   * @param sport
   * @param keystoreFile
   * @param keystorePasswd
   * @throws Exception
   */
  private void startHttpsServer(final int sport, String keystoreFile, String keystorePasswd) throws Exception {
    SSLContext sslContext = SSLContext.getInstance("TLS");
    
    KeyStore ks = KeyStore.getInstance("JKS");
    try (FileInputStream ksStream = new FileInputStream(keystoreFile)) {
      ks.load(ksStream, keystorePasswd.toCharArray());
    }
    
    KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
    kmf.init(ks, keystorePasswd.toCharArray());
    
    TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
    tmf.init(ks);
    
    sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
    
    
    HttpsServer sserver = HttpsServer.create(new InetSocketAddress(sport), 0);
    sserver.setHttpsConfigurator(new HttpsConfigurator(sslContext) {

      @Override
      public void configure(HttpsParameters params) {
        try {
          SSLContext c = SSLContext.getDefault();
          SSLEngine engine = c.createSSLEngine("localhost", sport);
          params.setNeedClientAuth(false);
          params.setCipherSuites(engine.getEnabledCipherSuites());
          params.setProtocols(engine.getEnabledProtocols());
          
          SSLParameters defaultSSLParams = c.getDefaultSSLParameters();
          params.setSSLParameters(defaultSSLParams);
          
        } catch (Exception ex) {
          log.log(Level.SEVERE, "startHttpsServe", ex);
        }
      }
      
    });
    
    sserver.createContext("/", this);
    sserver.setExecutor(null);
    sserver.start();
  }

  public void startHttpServer(int port) throws IOException {
    log.info("Starting server");
    HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
    server.createContext("/", this);
    server.setExecutor(null);
    server.start();
  }

  @Override
  public void handle(HttpExchange httpEx) throws IOException {
    if (receivedStop(httpEx)) {
      log.info("Received Stop Request");
      sendMessage(httpEx, "text/plain", stopResponse);
      httpEx.getHttpContext().getServer().stop(0);
    } else {
      log.info("Received request from " + httpEx.getRemoteAddress().toString());
      
      try (FileReader fr = new FileReader(this.messageFile)) {
        StringWriter sw = new StringWriter();
        CharBuffer cb = CharBuffer.allocate(300);
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
    httpEx.sendResponseHeaders(200, response.length());

    OutputStream os = httpEx.getResponseBody();
    os.write(response.getBytes());
    os.close();
  }

  private boolean receivedStop(HttpExchange httpEx) throws IOException {
    if (httpEx.getRequestMethod().equals("GET") && httpEx.getRequestURI().toString().equals(this.stopCmd)) {
      return true;
    }
    return false;
  }
}
