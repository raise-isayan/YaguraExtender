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

}
