package no.uis.httpdmaintain;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringWriter;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.CharBuffer;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.swing.JOptionPane;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

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
      int port = readIntArg(args, argIdx++, 8080);
      String fileName = readArg(args, argIdx++, "maintenance.html");
      
      if (cmd.equals("start")) {
        new MyServer(stopCmd).startServer(port, fileName);
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
    JOptionPane.showMessageDialog(null, "Usage:\n<cmd(start|stop)> <stopCmd> [port(8080)] [html(maintenance.html)]");
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
  
  private void startServer(int port, String msgFile) throws Exception {
    File file = new File(msgFile);
    if (file.canRead()) {
      messageFile = file;
    } else {
      throw new IllegalArgumentException("File " + msgFile + " does not exist");
    }
    log.info("Starting server");
    HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);

    server.createContext("/", this);
    server.setExecutor(null);
    server.start();
    log.info("Server started");
  }

  @Override
  public void handle(HttpExchange httpEx) throws IOException {
    if (receivedStop(httpEx)) {
      log.info("Received Stop Request");
      sendMessage(httpEx, "text/plain", stopResponse);
      httpEx.getHttpContext().getServer().stop(0);
    } else {
      log.info("Received request from " + httpEx.getRemoteAddress().toString());
      FileReader fr = new FileReader(this.messageFile);
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
