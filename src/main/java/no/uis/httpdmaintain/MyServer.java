package no.uis.httpdmaintain;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.InetSocketAddress;
import java.nio.CharBuffer;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

@SuppressWarnings("restriction")
public class MyServer implements HttpHandler {

  private File messageFile;

  public static void main(String[] args) {
    try {
      int port = 8080;
      String file = "maintenance.html";
      if (args.length > 0) {
        port = Integer.parseInt(args[0]);
        if (args.length > 1) {
          file = args[1];
        }
      }
      new MyServer().startServer(port, file);
    } catch(Exception e) {
      writeLog(e);
    }
  }

  private static void writeLog(Exception e) {
    try {
      FileWriter fw = new FileWriter("maintenance.log", true);
      e.printStackTrace(new PrintWriter(fw));
      fw.close();
    } catch(Exception ex) {
      // ignore
    }
  }

  private void startServer(int port, String msgFile) throws Exception {
    File file = new File(msgFile);
    if (file.canRead()) {
      messageFile = file;
    } else {
      throw new IllegalArgumentException("File " + msgFile + " does not exist");
    }
    HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);

    server.createContext("/", this);
    server.setExecutor(null);
    server.start();
  }

  @Override
  public void handle(HttpExchange httpEx) throws IOException {
    if (receivedStop(httpEx)) {
      httpEx.getHttpContext().getServer().stop(0);
    } else {
      FileReader fr = new FileReader(this.messageFile);
      StringWriter sw = new StringWriter();
      CharBuffer cb = CharBuffer.allocate(300);
      int nboRead = 0;
      while ((nboRead = fr.read(cb)) > 0) {
        String s = cb.clear().toString();
        sw.append(s, 0, nboRead);
      }
      String result = sw.toString();
      httpEx.sendResponseHeaders(200, result.length());

      OutputStream os = httpEx.getResponseBody();
      os.write(result.getBytes());
      os.close();
    }
  }

  private boolean receivedStop(HttpExchange httpEx) throws IOException {
    if (httpEx.getRequestMethod().equals("GET") && httpEx.getRequestURI().toString().equals("/STOP")) {
      return true;
    }
    return false;
  }
}
