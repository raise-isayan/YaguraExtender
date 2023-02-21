package yagura;

import burp.BurpExtension;
import extension.burp.MessageType;
import extension.helpers.StringUtil;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import yagura.model.AutoResponderItem;
import yagura.model.AutoResponderProperty;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import okio.Buffer;
import okio.Okio;

/**
 *
 * @author isayan
 */
public class AutoMockServer {
    private final static Logger logger = Logger.getLogger(AutoMockServer.class.getName());

    private final MockWebServer server = new MockWebServer();


    public AutoMockServer() {
    }

    private boolean running = false;

    public void startServer(int listenPort) {
        try {
            BurpExtension.helpers().issueAlert("MockServer", "start listen port:" + listenPort, MessageType.INFO);
            AutoResponderProperty autoResponder = BurpExtension.getInstance().getProperty().getAutoResponderProperty();
            final AutoResponderDispatcher dispacher = new AutoResponderDispatcher(autoResponder);
            this.server.setDispatcher(dispacher);
            this.server.start(listenPort);
            this.running = true;
        } catch (IOException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    public boolean isRunning() {
        return (this.running);
    }

    public void stopServer() {
        try {
            this.server.shutdown();
            this.running = false;
            BurpExtension.helpers().issueAlert("MockServer", "stop server", MessageType.INFO);
        } catch (IOException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    public URL serviceURL() {
        return server.url("/").url();
    }

    class AutoResponderDispatcher extends Dispatcher {
        private final AutoResponderProperty autoResponder;

        public AutoResponderDispatcher(AutoResponderProperty autoResponder) {
            this.autoResponder = autoResponder;
        }

        public static String getRequestURL(RecordedRequest request) {
            String requestURL = request.getHeader(AutoResponderProperty.AUTO_RESPONDER_HEADER);
            return requestURL;
        }

        @Override
        public MockResponse dispatch(RecordedRequest request) throws InterruptedException {
            try {
                if (request.getPath().startsWith("/")){
                    String reqestURL = getRequestURL(request);
                    BurpExtension.api().logging().logToOutput("request:" + reqestURL);
                    // Content-Type
                    AutoResponderItem item = autoResponder.findItem(reqestURL);
                    if (item != null) {
                        File replaceFile = new File(item.getReplace());
                        Buffer buffer = new Buffer();
                        buffer.writeAll(Okio.source(replaceFile));
                        if (replaceFile.exists()) {
                            return new MockResponse().addHeader("Content-Type", item.getContentType())
                                .setBody(buffer).setResponseCode(200);
                        }
                    }
                }
            } catch (IOException ex) {
                return new MockResponse().setResponseCode(500).setBody(StringUtil.getStackTrace(ex));
            }
            return new MockResponse().setResponseCode(404);
        }
    }
}
