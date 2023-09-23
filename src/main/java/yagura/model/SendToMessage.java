package yagura.model;

import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse.SelectionContext;
import java.util.List;
import java.util.Arrays;
import extension.helpers.StringUtil;
import java.nio.charset.StandardCharsets;

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

    public static SendToMessage newSendToMessage(MessageEditorHttpRequestResponse editorInfo, boolean extendVisible) {
        return new SendToMessage() {
            @Override
            public List<HttpRequestResponse> getSelectedMessages() {
                return List.of(editorInfo.requestResponse()) ;
            }

            @Override
            public String getSelectedText() {
                if (editorInfo.selectionContext() == SelectionContext.REQUEST && editorInfo.selectionOffsets().isPresent()) {
                    Range range = editorInfo.selectionOffsets().get();
                    return StringUtil.getStringCharset(editorInfo.requestResponse().request().toByteArray().getBytes(), range.startIndexInclusive(), range.endIndexExclusive() - range.startIndexInclusive(), StandardCharsets.ISO_8859_1);
                }
                else if (editorInfo.selectionContext() == SelectionContext.RESPONSE && editorInfo.selectionOffsets().isPresent()) {
                    Range range = editorInfo.selectionOffsets().get();
                    return StringUtil.getStringCharset(editorInfo.requestResponse().response().toByteArray().getBytes(), range.startIndexInclusive(), range.endIndexExclusive() - range.startIndexInclusive(), StandardCharsets.ISO_8859_1);
                }
                return null;
            }

            @Override
            public boolean isExtendVisible() {
                return extendVisible;
            }
        };
    }

}
