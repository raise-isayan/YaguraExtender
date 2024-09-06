[1mdiff --git a/release/YaguraExtension-v3.1.jar b/release/YaguraExtension-v3.1.jar[m
[1mindex 9b85c44..50ab168 100644[m
Binary files a/release/YaguraExtension-v3.1.jar and b/release/YaguraExtension-v3.1.jar differ
[1mdiff --git a/src/main/java/burp/BurpExtension.java b/src/main/java/burp/BurpExtension.java[m
[1mindex dcfaef0..aa30f92 100644[m
[1m--- a/src/main/java/burp/BurpExtension.java[m
[1m+++ b/src/main/java/burp/BurpExtension.java[m
[36m@@ -24,12 +24,21 @@[m [mimport burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;[m
 import burp.api.montoya.proxy.http.ProxyResponseHandler;[m
 import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;[m
 import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;[m
[32m+[m[32mimport burp.api.montoya.proxy.websocket.BinaryMessageReceivedAction;[m
[32m+[m[32mimport burp.api.montoya.proxy.websocket.BinaryMessageToBeSentAction;[m
[32m+[m[32mimport burp.api.montoya.proxy.websocket.InterceptedBinaryMessage;[m
[32m+[m[32mimport burp.api.montoya.proxy.websocket.InterceptedTextMessage;[m
[32m+[m[32mimport burp.api.montoya.proxy.websocket.ProxyMessageHandler;[m
[32m+[m[32mimport burp.api.montoya.proxy.websocket.ProxyWebSocketCreation;[m
[32m+[m[32mimport burp.api.montoya.proxy.websocket.TextMessageReceivedAction;[m
[32m+[m[32mimport burp.api.montoya.proxy.websocket.TextMessageToBeSentAction;[m
 import burp.api.montoya.scanner.audit.issues.AuditIssue;[m
 import burp.api.montoya.ui.editor.extension.EditorCreationContext;[m
 import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;[m
 import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;[m
 import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;[m
 import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;[m
[32m+[m[32mimport burp.api.montoya.proxy.websocket.ProxyWebSocketCreationHandler;[m
 import java.awt.Component;[m
 import java.awt.event.MouseAdapter;[m
 import java.awt.event.MouseEvent;[m
[36m@@ -157,6 +166,7 @@[m [mpublic class BurpExtension extends BurpExtensionImpl implements ExtensionUnloadi[m
 [m
     private MenuHander menuHandler;[m
     private ProxyHander proxyHandler;[m
[32m+[m[32m    private WebSocktCreationHander websocktHandler;[m
     private EditorProvider editorProvider;[m
     private AutoResponderHandler autoResponderHandler;[m
     private Registration registerContextMenu;[m
[36m@@ -281,6 +291,7 @@[m [mpublic class BurpExtension extends BurpExtensionImpl implements ExtensionUnloadi[m
             this.registerView();[m
             this.menuHandler = new MenuHander(api);[m
             this.proxyHandler = new ProxyHander(api);[m
[32m+[m[32m            this.websocktHandler = new WebSocktCreationHander(api);[m
             this.autoResponderHandler = new AutoResponderHandler(api);[m
             api.extension().registerUnloadingHandler(this);[m
 [m
[36m@@ -1802,6 +1813,70 @@[m [mpublic class BurpExtension extends BurpExtensionImpl implements ExtensionUnloadi[m
 [m
     }[m
 [m
[32m+[m[32m    protected final class WebSocktCreationHander implements ProxyWebSocketCreationHandler {[m
[32m+[m
[32m+[m[32m        private final MontoyaApi api;[m
[32m+[m
[32m+[m[32m        public WebSocktCreationHander(MontoyaApi api) {[m
[32m+[m[32m            this.api = api;[m
[32m+[m[32m            api.proxy().registerWebSocketCreationHandler(this);[m
[32m+[m[32m        }[m
[32m+[m
[32m+[m[32m        @Override[m
[32m+[m[32m        public void handleWebSocketCreation(ProxyWebSocketCreation proxyWebSocketCreation) {[m
[32m+[m[32m            proxyWebSocketCreation.proxyWebSocket().registerProxyMessageHandler(new WebSocktHander(api, proxyWebSocketCreation));[m
[32m+[m[32m        }[m
[32m+[m
[32m+[m[32m    }[m
[32m+[m
[32m+[m[32m    protected final class WebSocktHander implements ProxyMessageHandler {[m
[32m+[m[32m        private final MontoyaApi api;[m
[32m+[m[32m        private final ProxyWebSocketCreation proxyWebSocketCreation;[m
[32m+[m
[32m+[m[32m        public WebSocktHander(MontoyaApi api, ProxyWebSocketCreation proxyWebSocketCreation) {[m
[32m+[m[32m            this.api = api;[m
[32m+[m[32m            this.proxyWebSocketCreation = proxyWebSocketCreation;[m
[32m+[m[32m            proxyWebSocketCreation.proxyWebSocket().registerProxyMessageHandler(this);[m
[32m+[m[32m        }[m
[32m+[m
[32m+[m[32m        @Override[m
[32m+[m[32m        public TextMessageReceivedAction handleTextMessageReceived(InterceptedTextMessage interceptedTextMessage) {[m
[32m+[m[32m            // WebSockt 出力[m
[32m+[m[32m            if (getProperty().getLoggingProperty().isAutoLogging() && getProperty().getLoggingProperty().isWebSocktLog()) {[m
[32m+[m[32m                logging.writeWebSocktFinalMessage(proxyWebSocketCreation, interceptedTextMessage);[m
[32m+[m[32m            }[m
[32m+[m[32m            return TextMessageReceivedAction.continueWith(interceptedTextMessage);[m
[32m+[m[32m        }[m
[32m+[m
[32m+[m[32m        @Override[m
[32m+[m[32m        public TextMessageToBeSentAction handleTextMessageToBeSent(InterceptedTextMessage interceptedTextMessage) {[m
[32m+[m[32m            // WebSockt 出力[m
[32m+[m[32m            if (getProperty().getLoggingProperty().isAutoLogging() && getProperty().getLoggingProperty().isWebSocktLog()) {[m
[32m+[m[32m                logging.writeWebSocktFinalMessage(proxyWebSocketCreation, interceptedTextMessage);[m
[32m+[m[32m            }[m
[32m+[m[32m            return TextMessageToBeSentAction.continueWith(interceptedTextMessage);[m
[32m+[m[32m        }[m
[32m+[m
[32m+[m[32m        @Override[m
[32m+[m[32m        public BinaryMessageReceivedAction handleBinaryMessageReceived(InterceptedBinaryMessage interceptedBinaryMessage) {[m
[32m+[m[32m            // WebSockt 出力[m
[32m+[m[32m            if (getProperty().getLoggingProperty().isAutoLogging() && getProperty().getLoggingProperty().isWebSocktLog()) {[m
[32m+[m[32m                logging.writeWebSocktFinalMessage(proxyWebSocketCreation, interceptedBinaryMessage);[m
[32m+[m[32m            }[m
[32m+[m[32m            return BinaryMessageReceivedAction.continueWith(interceptedBinaryMessage);[m
[32m+[m[32m        }[m
[32m+[m
[32m+[m[32m        @Override[m
[32m+[m[32m        public BinaryMessageToBeSentAction handleBinaryMessageToBeSent(InterceptedBinaryMessage interceptedBinaryMessage) {[m
[32m+[m[32m            // WebSockt 出力[m
[32m+[m[32m            if (getProperty().getLoggingProperty().isAutoLogging() && getProperty().getLoggingProperty().isWebSocktLog()) {[m
[32m+[m[32m                logging.writeWebSocktFinalMessage(proxyWebSocketCreation, interceptedBinaryMessage);[m
[32m+[m[32m            }[m
[32m+[m[32m            return BinaryMessageToBeSentAction.continueWith(interceptedBinaryMessage);[m
[32m+[m[32m        }[m
[32m+[m
[32m+[m[32m    }[m
[32m+[m
     protected class AutoResponderHandler implements HttpHandler, ProxyRequestHandler, ExtensionUnloadingHandler {[m
 [m
         private final MontoyaApi api;[m
[1mdiff --git a/src/main/java/yagura/Config.java b/src/main/java/yagura/Config.java[m
[1mindex d9b3d11..6445de4 100644[m
[1m--- a/src/main/java/yagura/Config.java[m
[1m+++ b/src/main/java/yagura/Config.java[m
[36m@@ -36,6 +36,14 @@[m [mpublic class Config extends BurpConfig {[m
         return "proxy-message.log";[m
     }[m
 [m
[32m+[m[32m    public static String getWebSocktLogMessageName() {[m
[32m+[m[32m        return "websockt-message.log";[m
[32m+[m[32m    }[m
[32m+[m
[32m+[m[32m    public static String getWebSocktLogFinalMessageName() {[m
[32m+[m[32m        return "websockt-final-message.log";[m
[32m+[m[32m    }[m
[32m+[m
     public static String getToolLogName(String toolName) {[m
         return String.format("burp_tool_%s.log", toolName);[m
     }[m
[1mdiff --git a/src/main/java/yagura/model/Logging.java b/src/main/java/yagura/model/Logging.java[m
[1mindex 1207581..138db2e 100644[m
[1m--- a/src/main/java/yagura/model/Logging.java[m
[1m+++ b/src/main/java/yagura/model/Logging.java[m
[36m@@ -5,6 +5,9 @@[m [mimport burp.api.montoya.http.HttpService;[m
 import burp.api.montoya.http.message.HttpRequestResponse;[m
 import burp.api.montoya.http.message.requests.HttpRequest;[m
 import burp.api.montoya.http.message.responses.HttpResponse;[m
[32m+[m[32mimport burp.api.montoya.proxy.websocket.ProxyWebSocketCreation;[m
[32m+[m[32mimport burp.api.montoya.websocket.BinaryMessage;[m
[32m+[m[32mimport burp.api.montoya.websocket.TextMessage;[m
 import extension.burp.BurpUtil;[m
 import extension.burp.HttpTarget;[m
 import extension.helpers.ConvertUtil;[m
[36m@@ -339,4 +342,73 @@[m [mpublic class Logging implements Closeable {[m
         }[m
     }[m
 [m
[32m+[m[32m    public void writeWebSocktMessageOriginal(final ProxyWebSocketCreation proxyWebSocketCreation, TextMessage textMessage) {[m
[32m+[m[32m        String baseLogFileName = Config.getWebSocktLogMessageName();[m
[32m+[m[32m        this.writeWebSocktMessage(baseLogFileName, proxyWebSocketCreation, textMessage);[m
[32m+[m[32m    }[m
[32m+[m
[32m+[m[32m    public void writeWebSocktFinalMessage(final ProxyWebSocketCreation proxyWebSocketCreation, TextMessage textMessage) {[m
[32m+[m[32m        String baseLogFileName = Config.getWebSocktLogFinalMessageName();[m
[32m+[m[32m        this.writeWebSocktMessage(baseLogFileName, proxyWebSocketCreation, textMessage);[m
[32m+[m[32m    }[m
[32m+[m
[32m+[m[32m    protected synchronized void writeWebSocktMessage(String baseLogFileName, final ProxyWebSocketCreation proxyWebSocketCreation, TextMessage textMessage) {[m
[32m+[m[32m        try {[m
[32m+[m[32m            Path path = getLoggingPath(baseLogFileName);[m
[32m+[m[32m            try (OutputStream ostm = Files.newOutputStream(path, StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {[m
[32m+[m[32m                writeWebSocktTextMessage(ostm, proxyWebSocketCreation, textMessage);[m
[32m+[m[32m                ostm.flush();[m
[32m+[m[32m            }[m
[32m+[m[32m        } catch (IOException ex) {[m
[32m+[m[32m            logger.log(Level.SEVERE, ex.getMessage(), ex);[m
[32m+[m[32m        } catch (Exception ex) {[m
[32m+[m[32m            logger.log(Level.SEVERE, ex.getMessage(), ex);[m
[32m+[m[32m        }[m
[32m+[m[32m    }[m
[32m+[m
[32m+[m[32m    public void writeWebSocktMessageOriginal(final ProxyWebSocketCreation proxyWebSocketCreation, BinaryMessage binaryMessage) {[m
[32m+[m[32m        String baseLogFileName = Config.getWebSocktLogMessageName();[m
[32m+[m[32m        this.writeWebSocktMessage(baseLogFileName, proxyWebSocketCreation, binaryMessage);[m
[32m+[m[32m    }[m
[32m+[m
[32m+[m[32m    public void writeWebSocktFinalMessage(final ProxyWebSocketCreation proxyWebSocketCreation, BinaryMessage binaryMessage) {[m
[32m+[m[32m        String baseLogFileName = Config.getWebSocktLogFinalMessageName();[m
[32m+[m[32m        this.writeWebSocktMessage(baseLogFileName, proxyWebSocketCreation, binaryMessage);[m
[32m+[m[32m    }[m
[32m+[m
[32m+[m[32m    public void writeWebSocktMessage(String baseLogFileName, final ProxyWebSocketCreation proxyWebSocketCreation, BinaryMessage binaryMessage) {[m
[32m+[m[32m        try {[m
[32m+[m[32m            Path path = getLoggingPath(baseLogFileName);[m
[32m+[m[32m            try (OutputStream ostm = Files.newOutputStream(path, StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {[m
[32m+[m[32m                writeWebSocktBinayMessage(ostm, proxyWebSocketCreation, binaryMessage);[m
[32m+[m[32m                ostm.flush();[m
[32m+[m[32m            }[m
[32m+[m[32m        } catch (IOException ex) {[m
[32m+[m[32m            logger.log(Level.SEVERE, ex.getMessage(), ex);[m
[32m+[m[32m        } catch (Exception ex) {[m
[32m+[m[32m            logger.log(Level.SEVERE, ex.getMessage(), ex);[m
[32m+[m[32m        }[m
[32m+[m[32m    }[m
[32m+[m
[32m+[m[32m    protected void writeWebSocktTextMessage(OutputStream ostm, ProxyWebSocketCreation proxyWebSocketCreation, TextMessage textMessage) throws IOException {[m
[32m+[m[32m        try (BufferedOutputStream fostm = new BufferedOutputStream(ostm)) {[m
[32m+[m[32m            fostm.write(StringUtil.getBytesRaw("======================================================" + HttpUtil.LINE_TERMINATE));[m
[32m+[m[32m            fostm.write(StringUtil.getBytesRaw(getLoggingProperty().getCurrentLogTimestamp() + " " + textMessage.direction().name() + " " + proxyWebSocketCreation.upgradeRequest().url() + HttpUtil.LINE_TERMINATE));[m
[32m+[m[32m            fostm.write(StringUtil.getBytesRaw("======================================================" + HttpUtil.LINE_TERMINATE));[m
[32m+[m[32m            fostm.write(StringUtil.getBytesRaw(textMessage.payload() + HttpUtil.LINE_TERMINATE));[m
[32m+[m[32m            fostm.write(StringUtil.getBytesRaw("======================================================" + HttpUtil.LINE_TERMINATE));[m
[32m+[m[32m        }[m
[32m+[m[32m    }[m
[32m+[m
[32m+[m[32m    protected void writeWebSocktBinayMessage(OutputStream ostm, ProxyWebSocketCreation proxyWebSocketCreation, BinaryMessage binaryMessage) throws IOException {[m
[32m+[m[32m        try (BufferedOutputStream fostm = new BufferedOutputStream(ostm)) {[m
[32m+[m[32m            fostm.write(StringUtil.getBytesRaw("======================================================" + HttpUtil.LINE_TERMINATE));[m
[32m+[m[32m            fostm.write(StringUtil.getBytesRaw(getLoggingProperty().getCurrentLogTimestamp() + " " + binaryMessage.direction().name() + " " + proxyWebSocketCreation.upgradeRequest().url() + HttpUtil.LINE_TERMINATE));[m
[32m+[m[32m            fostm.write(StringUtil.getBytesRaw("======================================================" + HttpUtil.LINE_TERMINATE));[m
[32m+[m[32m            fostm.write(binaryMessage.payload().getBytes());[m
[32m+[m[32m            fostm.write(StringUtil.getBytesRaw(HttpUtil.LINE_TERMINATE));[m
[32m+[m[32m            fostm.write(StringUtil.getBytesRaw("======================================================" + HttpUtil.LINE_TERMINATE));[m
[32m+[m[32m        }[m
[32m+[m[32m    }[m
[32m+[m
 }[m
[1mdiff --git a/src/main/java/yagura/model/LoggingProperty.java b/src/main/java/yagura/model/LoggingProperty.java[m
[1mindex dffb68a..9ca4376 100644[m
[1m--- a/src/main/java/yagura/model/LoggingProperty.java[m
[1m+++ b/src/main/java/yagura/model/LoggingProperty.java[m
[36m@@ -97,6 +97,17 @@[m [mpublic class LoggingProperty implements IPropertyConfig {[m
         this.toolLog = toolLog;[m
     }[m
 [m
[32m+[m[32m    @Expose[m
[32m+[m[32m    private boolean websocktLog = true;[m
[32m+[m
[32m+[m[32m    public boolean isWebSocktLog() {[m
[32m+[m[32m        return this.websocktLog;[m
[32m+[m[32m    }[m
[32m+[m
[32m+[m[32m    public void setWebSocktLog(boolean websocktLog) {[m
[32m+[m[32m        this.websocktLog = websocktLog;[m
[32m+[m[32m    }[m
[32m+[m
     @Expose[m
     private String logDirFormat = DEFAULT_LOG_DIR_FORMAT;[m
 [m
[36m@@ -197,6 +208,7 @@[m [mpublic class LoggingProperty implements IPropertyConfig {[m
         this.setLogFileLimitSize(property.getLogFileLimitSize());[m
         this.setProxyLog(property.isProxyLog());[m
         this.setToolLog(property.isToolLog());[m
[32m+[m[32m        this.setWebSocktLog(property.isWebSocktLog());[m
         this.setLogDirFormat(property.getLogDirFormat());[m
         this.setLogTimestampFormat(property.getLogTimestampFormat());[m
         this.setExclude(property.isExclude());[m
