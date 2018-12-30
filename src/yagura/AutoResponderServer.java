package yagura;

import burp.BurpExtender;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import extend.util.Util;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.util.logging.Level;
import java.util.logging.Logger;
import yagura.model.AutoResponderItem;
import yagura.model.AutoResponderProperty;

/**
 *
 * @author isayan
 */
public class AutoResponderServer {

    private HttpServer server = null;

    public AutoResponderServer() {
    }

    public void startServer(int listenPort) throws IOException {
        System.out.println("start listen port:" + listenPort);
        this.server = HttpServer.create(new InetSocketAddress(listenPort), 0);
        this.server.createContext("/", new MyHandler());
        this.server.setExecutor(null); // creates a default executor
        this.server.start();
    }

    public boolean isRunning() {
        return (this.server != null);
    }

    public void stopServer() {
        if (this.server != null) {
            this.server.stop(1);
            System.out.println("stop server");
        }
        this.server = null;
    }

    static class MyHandler implements HttpHandler {
        private AutoResponderProperty autoResponder = null;

        public MyHandler() {
            autoResponder = BurpExtender.getInstance().getProperty().getAutoResponderProperty();
        }

        @Override
        public void handle(HttpExchange he) throws IOException {
            String requestURL = getRequestURL(he);

            // RequestBody Read
            byte requestBody[] = new byte[0];
            try (ByteArrayOutputStream bostm = new ByteArrayOutputStream()) {
                byte buff[] = new byte[2048];
                try (InputStream is = he.getRequestBody()) {
                    int len = 0;
                    while ((len = is.read(buff)) > -1) {
                        bostm.write(buff, 0, len);
                    }
                    requestBody = bostm.toByteArray();
                }

                // Content-Type
                AutoResponderItem item = autoResponder.findItem(requestURL);
                if (item != null) {
                    File replaceFile = new File(item.getReplace());
                    if (replaceFile.exists()) {
                        byte [] responseBody = Util.bytesFromFile(replaceFile);
                        he.getResponseHeaders().add("Content-Type", item.getContentType());
                        he.sendResponseHeaders(HttpURLConnection.HTTP_OK, responseBody.length);
                        try (OutputStream os = he.getResponseBody()) {
                            os.write(responseBody);
                        }
                    }
                }
            }
        }
    }

    public static String getRequestURL(HttpExchange he) {
        String url = null;
        if (he.getRequestHeaders().containsKey("X-AutoResponder")) {
            String protocol = he.getProtocol();
            url = he.getRequestHeaders().getFirst("X-AutoResponder");       
        }        
        return url;
    }
    
    public static class ThreadWrap extends Thread {

        private final AutoResponderServer server = new AutoResponderServer();
        private final int listenPort;

        public ThreadWrap(int listenPort) {
            this.listenPort = listenPort;
        }

        public void startServer() {
            this.start();
        }

        @Override
        public void run() {
            try {
                this.server.startServer(this.listenPort);
            } catch (IOException ex) {
                UncaughtExceptionHandler handler = this.getUncaughtExceptionHandler();
                if (handler != null) {
                    handler.uncaughtException(this, ex);
                }
                Logger.getLogger(ThreadWrap.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        public boolean isRunning() {
            return this.server.isRunning();
        }

        public void stopServer() {
            this.server.stopServer();
        }
    }

}
