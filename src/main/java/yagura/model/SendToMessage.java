package yagura.model;

import java.util.List;
import burp.api.montoya.http.message.HttpRequestResponse;

/**
 *
 * @author isayan
 */
public interface SendToMessage {

    public List<HttpRequestResponse> getSelectedMessages();

    public String getSelectedText();

    public boolean isExtendVisible();

    public static SendToMessage newSendToMessage(List<HttpRequestResponse> messageInfo, boolean extendVisible) {
        return new SendToMessage() {
            @Override
            public List<HttpRequestResponse> getSelectedMessages() {
                return messageInfo;
            }

            @Override
            public String getSelectedText() {
                return null;
            }

            @Override
            public boolean isExtendVisible() {
                return extendVisible;
            }
        };
    }

}
