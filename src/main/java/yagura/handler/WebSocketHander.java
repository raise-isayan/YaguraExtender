package yagura.handler;

import burp.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
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
import extension.burp.ProtocolType;
import extension.helpers.StringUtil;
import java.util.List;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import yagura.model.Logging;
import yagura.model.MatchReplaceItem;

/**
 *
 * @author isayan
 */
public class WebSocketHander implements ProxyWebSocketCreationHandler, WebSocketCreatedHandler {

    private final static Logger logger = Logger.getLogger(WebSocketHander.class.getName());

    private final MontoyaApi api;
    private final BurpExtension extenderImpl;

    public WebSocketHander(MontoyaApi api) {
        this.api = api;
        this.extenderImpl = BurpExtension.getInstance();
        api.proxy().registerWebSocketCreationHandler(this);
        api.websockets().registerWebSocketCreatedHandler(this);
    }

    @Override
    public void handleWebSocketCreation(ProxyWebSocketCreation proxyWebSocketCreation) {
        proxyWebSocketCreation.proxyWebSocket().registerProxyMessageHandler(new WebSocketProxyMessageHander(api, proxyWebSocketCreation));
    }

    @Override
    public void handleWebSocketCreated(WebSocketCreated webSocketCreated) {
        webSocketCreated.webSocket().registerMessageHandler(new WebSocketMessageHander(api, webSocketCreated));
    }

    static class WebSocketMessageHander implements MessageHandler {

        private final MontoyaApi api;
        private final WebSocketCreated webSocketCreated;
        private final BurpExtension extenderImpl;
        private final Logging logging;

        public WebSocketMessageHander(MontoyaApi api, WebSocketCreated webSocketCreated) {
            this.api = api;
            this.webSocketCreated = webSocketCreated;
            this.extenderImpl = BurpExtension.getInstance();
            this.logging = extenderImpl.getLogging();
        }

        @Override
        public TextMessageAction handleTextMessage(TextMessage textMessage) {
            // WebSocket 出力
            if (this.extenderImpl.getProperty().getLoggingProperty().isAutoLogging() && this.extenderImpl.getProperty().getLoggingProperty().isWebSocketLog()) {
                // Tool Log 出力
                ToolSource toolSource = webSocketCreated.toolSource();
                logging.writeWebSocketToolMessage(toolSource.toolType(), webSocketCreated, textMessage);
            }
            return TextMessageAction.continueWith(textMessage);
        }

        @Override
        public BinaryMessageAction handleBinaryMessage(BinaryMessage binaryMessage) {
            // WebSocket 出力
            if (this.extenderImpl.getProperty().getLoggingProperty().isAutoLogging() && this.extenderImpl.getProperty().getLoggingProperty().isWebSocketLog()) {
                // Tool Log 出力
                ToolSource toolSource = webSocketCreated.toolSource();
                logging.writeWebSocektToolMessage(toolSource.toolType(), webSocketCreated, binaryMessage);
            }
            return BinaryMessageAction.continueWith(binaryMessage);
        }

    }

    static class WebSocketProxyMessageHander implements ProxyMessageHandler {

        private final MontoyaApi api;
        private final ProxyWebSocketCreation proxyWebSocketCreation;
        private final BurpExtension extenderImpl;
        private final Logging logging;

        public WebSocketProxyMessageHander(MontoyaApi api, ProxyWebSocketCreation proxyWebSocketCreation) {
            this.api = api;
            this.proxyWebSocketCreation = proxyWebSocketCreation;
            this.extenderImpl = BurpExtension.getInstance();
            this.logging = extenderImpl.getLogging();
            proxyWebSocketCreation.proxyWebSocket().registerProxyMessageHandler(this);
        }

        @Override
        public TextMessageReceivedAction handleTextMessageReceived(InterceptedTextMessage interceptedTextMessage) {
            TextMessage requestResult = this.replaceProxyMessage(interceptedTextMessage);
            // WebSocket 出力
            if (extenderImpl.getProperty().getLoggingProperty().isAutoLogging() && extenderImpl.getProperty().getLoggingProperty().isWebSocketLog()
                    && interceptedTextMessage.direction() == Direction.SERVER_TO_CLIENT) {
                logging.writeWebSocketFinalMessage(this.proxyWebSocketCreation, interceptedTextMessage);
            }
            return TextMessageReceivedAction.continueWith(requestResult);
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
            BinaryMessage requestResult = this.replaceProxyMessage(interceptedBinaryMessage);
            // WebSocket 出力
            if (extenderImpl.getProperty().getLoggingProperty().isAutoLogging() && extenderImpl.getProperty().getLoggingProperty().isWebSocketLog()
                    && interceptedBinaryMessage.direction() == Direction.SERVER_TO_CLIENT) {
                logging.writeWebSocketFinalMessage(proxyWebSocketCreation, interceptedBinaryMessage);
            }
            return BinaryMessageReceivedAction.continueWith(requestResult);
        }

        @Override
        public BinaryMessageToBeSentAction handleBinaryMessageToBeSent(InterceptedBinaryMessage interceptedBinaryMessage) {
            // WebSocket 出力
            if (extenderImpl.getProperty().getLoggingProperty().isAutoLogging() && extenderImpl.getProperty().getLoggingProperty().isWebSocketLog()
                    && interceptedBinaryMessage.direction() == Direction.CLIENT_TO_SERVER) {
                logging.writeWebSocketFinalMessage(proxyWebSocketCreation, interceptedBinaryMessage);
            }
            return BinaryMessageToBeSentAction.continueWith(interceptedBinaryMessage);
        }

        /**
         * @message @return
         */
        private TextMessage replaceProxyMessage(TextMessage message) {
            byte[] payload = message.payload().getBytes();
            byte[] update = replaceProxyMessage(message.direction(), payload);
            if (payload != update) {
                return createTextMessage(message.direction(), StringUtil.getStringRaw(update));
            } else {
                return message;
            }
        }

        /**
         * @message @return
         */
        private BinaryMessage replaceProxyMessage(BinaryMessage message) {
            byte[] payload = message.payload().getBytes();
            byte[] update = replaceProxyMessage(message.direction(), payload);
            if (payload != update) {
                return createBinaryMessage(message.direction(), ByteArray.byteArray(update));
            } else {
                return message;
            }
        }

        private byte[] replaceProxyMessage(
                Direction direction,
                byte[] payload) {

            // headerとbodyに分割
            boolean edited = false;
            String message = StringUtil.getStringRaw(payload);
            List<MatchReplaceItem> matchReplaceList = extenderImpl.getProperty().getMatchReplaceProperty().getMatchReplaceList(ProtocolType.WEBSOCKET);
            for (int i = 0; i < matchReplaceList.size(); i++) {
                MatchReplaceItem bean = matchReplaceList.get(i);
                if (!bean.isSelected()) {
                    continue;
                }
                if (bean.isClientToServer() || bean.isServerToClient()) {
                    Pattern pattern = bean.getRegexPattern();
                    if ((bean.isClientToServer() && direction == Direction.CLIENT_TO_SERVER) || (bean.isServerToClient() && direction == Direction.SERVER_TO_CLIENT)) {
                        Matcher m = pattern.matcher(message);
                        if (m.find()) {
                            message = m.replaceAll(bean.getReplace(!bean.isRegexp(), bean.isMetaChar()));
                            edited = true;
                        }
                    }
                }
            }
            if (edited) {
                payload = StringUtil.getBytesRaw(message);
            }
            return payload;
        }
    }

    public static TextMessage createTextMessage(final Direction direction, final String payload) {
        return new TextMessage() {
            @Override
            public String payload() {
                return payload;
            }

            @Override
            public Direction direction() {
                return direction;
            }
        };
    }

    public static BinaryMessage createBinaryMessage(final Direction direction, final ByteArray payload) {
        return new BinaryMessage() {
            @Override
            public ByteArray payload() {
                return payload;
            }

            @Override
            public Direction direction() {
                return direction;
            }
        };
    }

}
