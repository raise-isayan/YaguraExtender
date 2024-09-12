package yagura;

import burp.BurpExtension;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.responses.HttpResponse;
import extension.burp.MessageType;
import extension.helpers.StringUtil;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.nio.file.Files;
import java.util.List;
import okhttp3.Headers;
import java.util.stream.Collectors;
import yagura.model.AutoResponderItem;
import yagura.model.AutoResponderProperty;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
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

    private MockWebServer server = null;

    public AutoMockServer() {
    }

    public void startServer(int listenPort) {
        try {
            final BurpExtension extenderImpl = BurpExtension.getInstance();

            BurpExtension.helpers().issueAlert("MockServer", "start listen port:" + listenPort, MessageType.INFO);
            AutoResponderProperty autoResponder = extenderImpl.getProperty().getAutoResponderProperty();
            final AutoResponderDispatcher dispacher = new AutoResponderDispatcher(autoResponder);
            this.server = new MockWebServer();
            this.server.setDispatcher(dispacher);
            this.server.start(listenPort);
            this.server.setProtocolNegotiationEnabled(true);
        } catch (IOException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    public boolean isRunning() {
        return (this.server != null);
    }

    public void stopServer() {
        try {
            if (isRunning()) {
                this.server.shutdown();
                this.server = null;
            }
            BurpExtension.helpers().issueAlert("MockServer", "stop server", MessageType.INFO);
            BurpExtension.api().logging().logToOutput("MockServer stop serve:" + StringUtil.currentStackTrace());
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
            MockResponse mockResponse = new MockResponse();
            try {
                if (request.getPath().startsWith("/")) {
                    String reqestURL = getRequestURL(request);
                    // Content-Type
                    AutoResponderItem item = this.autoResponder.findItem(reqestURL, request.getMethod());
                    if (item != null) {
                        File replaceFile = new File(item.getReplace());
                        if (item.isBodyOnly()) {
                            Buffer buffer = new Buffer();
                            buffer.writeAll(Okio.source(replaceFile));
                            if (replaceFile.exists()) {
                                return mockResponse
                                        .addHeader("Content-Type", item.getContentType())
                                        .setBody(buffer)
                                        .setResponseCode(200);
                            }
                        } else {
                            byte[] reqRaw = Files.readAllBytes(replaceFile.toPath());
                            HttpResponse httpResponse = HttpResponse.httpResponse(ByteArray.byteArray(reqRaw));

                            List<HttpHeader> headerList = httpResponse.headers().stream().collect(Collectors.toList());
                            Headers.Builder headers = new Headers.Builder();
                            for (int i = 0; i < headerList.size(); i++) {
                                HttpHeader h = headerList.get(i);
                                headers.add(h.name(), h.value());
                            }
                            Buffer buffer = new Buffer();
                            buffer.write(httpResponse.body().getBytes());
                            return mockResponse
                                    .setHeaders(headers.build())
                                    .setBody(buffer)
                                    .setResponseCode(httpResponse.statusCode());
                        }
                    }
                }
            } catch (IOException ex) {
                return mockResponse.setResponseCode(500).setBody(StringUtil.getStackTrace(ex));
            }
            return mockResponse.setResponseCode(404);
        }
    }
}
