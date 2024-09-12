package yagura.handler;

import burp.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.proxy.websocket.BinaryMessageReceivedAction;
import burp.api.montoya.proxy.websocket.BinaryMessageToBeSentAction;
import burp.api.montoya.proxy.websocket.InterceptedBinaryMessage;
import burp.api.montoya.proxy.websocket.InterceptedTextMessage;
import burp.api.montoya.proxy.websocket.ProxyMessageHandler;
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreation;
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreationHandler;
import burp.api.montoya.proxy.websocket.TextMessageReceivedAction;
import burp.api.montoya.proxy.websocket.TextMessageToBeSentAction;
import burp.api.montoya.websocket.BinaryMessage;
import burp.api.montoya.websocket.BinaryMessageAction;
import burp.api.montoya.websocket.Direction;
import burp.api.montoya.websocket.MessageHandler;
import burp.api.montoya.websocket.TextMessage;
import burp.api.montoya.websocket.TextMessageAction;
import burp.api.montoya.websocket.WebSocketCreated;
import burp.api.montoya.websocket.WebSocketCreatedHandler;
import java.util.logging.Logger;
import yagura.model.Logging;

/**
 *
 * @author isayan
 */
public class WebSocketHander implements ProxyWebSocketCreationHandler, WebSocketCreatedHandler {

    private final static Logger logger = Logger.getLogger(WebSocketHander.class.getName());

    private final MontoyaApi api;

    public WebSocketHander(MontoyaApi api) {
        this.api = api;
        api.proxy().registerWebSocketCreationHandler(this);
        api.websockets().registerWebSocketCreatedHandler(this);
    }

    @Override
    public void handleWebSocketCreation(ProxyWebSocketCreation proxyWebSocketCreation) {
        proxyWebSocketCreation.proxyWebSocket().registerProxyMessageHandler(new WebSocktProxyMessageHander(api, proxyWebSocketCreation));
    }

    @Override
    public void handleWebSocketCreated(WebSocketCreated webSocketCreated) {
        webSocketCreated.webSocket().registerMessageHandler(new WebSocktMessageHander(api, webSocketCreated));
    }

    static class WebSocktMessageHander implements MessageHandler {

        private final MontoyaApi api;
        private final WebSocketCreated webSocketCreated;
        private final BurpExtension extenderImpl;
        private final Logging logging;

        public WebSocktMessageHander(MontoyaApi api, WebSocketCreated webSocketCreated) {
            this.api = api;
            this.webSocketCreated = webSocketCreated;
            this.extenderImpl = BurpExtension.getInstance();
            this.logging = extenderImpl.getLogging();
        }

        @Override
        public TextMessageAction handleTextMessage(TextMessage textMessage) {
            // WebSockt 出力
            if (this.extenderImpl.getProperty().getLoggingProperty().isAutoLogging() && this.extenderImpl.getProperty().getLoggingProperty().isWebSocketLog()) {
                ToolSource toolSource = webSocketCreated.toolSource();
                logging.writeWebSocketToolMessage(toolSource.toolType(), webSocketCreated, textMessage);
            }
            return TextMessageAction.continueWith(textMessage);
        }

        @Override
        public BinaryMessageAction handleBinaryMessage(BinaryMessage binaryMessage) {
            // WebSockt 出力
            if (this.extenderImpl.getProperty().getLoggingProperty().isAutoLogging() && this.extenderImpl.getProperty().getLoggingProperty().isWebSocketLog()) {
                ToolSource toolSource = webSocketCreated.toolSource();
                logging.writeWebSocektToolMessage(toolSource.toolType(), webSocketCreated, binaryMessage);
            }
            return BinaryMessageAction.continueWith(binaryMessage);
        }

    }

    static class WebSocktProxyMessageHander implements ProxyMessageHandler {

        private final MontoyaApi api;
        private final ProxyWebSocketCreation proxyWebSocketCreation;
        private final BurpExtension extenderImpl;
        private final Logging logging;

        public WebSocktProxyMessageHander(MontoyaApi api, ProxyWebSocketCreation proxyWebSocketCreation) {
            this.api = api;
            this.proxyWebSocketCreation = proxyWebSocketCreation;
            this.extenderImpl = BurpExtension.getInstance();
            this.logging = extenderImpl.getLogging();
            proxyWebSocketCreation.proxyWebSocket().registerProxyMessageHandler(this);
        }

        @Override
        public TextMessageReceivedAction handleTextMessageReceived(InterceptedTextMessage interceptedTextMessage) {
            // WebSockt 出力
            if (extenderImpl.getProperty().getLoggingProperty().isAutoLogging() && extenderImpl.getProperty().getLoggingProperty().isWebSocketLog()
                    && interceptedTextMessage.direction() == Direction.SERVER_TO_CLIENT) {
                logging.writeWebSocketFinalMessage(this.proxyWebSocketCreation, interceptedTextMessage);
            }
            return TextMessageReceivedAction.continueWith(interceptedTextMessage);
        }

        @Override
        public TextMessageToBeSentAction handleTextMessageToBeSent(InterceptedTextMessage interceptedTextMessage) {
            // WebSockt 出力
            if (extenderImpl.getProperty().getLoggingProperty().isAutoLogging() && extenderImpl.getProperty().getLoggingProperty().isWebSocketLog()
                    && interceptedTextMessage.direction() == Direction.CLIENT_TO_SERVER) {
                logging.writeWebSocketFinalMessage(proxyWebSocketCreation, interceptedTextMessage);
            }
            return TextMessageToBeSentAction.continueWith(interceptedTextMessage);
        }

        @Override
        public BinaryMessageReceivedAction handleBinaryMessageReceived(InterceptedBinaryMessage interceptedBinaryMessage) {
            // WebSockt 出力
            if (extenderImpl.getProperty().getLoggingProperty().isAutoLogging() && extenderImpl.getProperty().getLoggingProperty().isWebSocketLog()
                    && interceptedBinaryMessage.direction() == Direction.SERVER_TO_CLIENT) {
                logging.writeWebSocketFinalMessage(proxyWebSocketCreation, interceptedBinaryMessage);
            }
            return BinaryMessageReceivedAction.continueWith(interceptedBinaryMessage);
        }

        @Override
        public BinaryMessageToBeSentAction handleBinaryMessageToBeSent(InterceptedBinaryMessage interceptedBinaryMessage) {
            // WebSockt 出力
            if (extenderImpl.getProperty().getLoggingProperty().isAutoLogging() && extenderImpl.getProperty().getLoggingProperty().isWebSocketLog()
                    && interceptedBinaryMessage.direction() == Direction.CLIENT_TO_SERVER) {
                logging.writeWebSocketFinalMessage(proxyWebSocketCreation, interceptedBinaryMessage);
            }
            return BinaryMessageToBeSentAction.continueWith(interceptedBinaryMessage);
        }

    }

}
