package yagura.view;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.contextmenu.WebSocketMessage;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedWebSocketMessageEditor;
import java.awt.Component;

/**
 *
 * @author isayan
 */
public class GenerateWebsocktPoCEditor implements ExtensionProvidedWebSocketMessageEditor {

    private final GenerateWebsocktPoCTab tabGeneratePoC;

    public GenerateWebsocktPoCEditor(EditorCreationContext editorCreationContext) {
        this.tabGeneratePoC = new GenerateWebsocktPoCTab();
    }

    @Override
    public ByteArray getMessage() {
        return this.tabGeneratePoC.getMessage();
    }

    @Override
    public void setMessage(WebSocketMessage webSocketMessage) {
        this.tabGeneratePoC.setMessage(webSocketMessage);
    }

    @Override
    public boolean isEnabledFor(WebSocketMessage webSocketMessage) {
        return this.tabGeneratePoC.isEnabledFor(webSocketMessage);
    }

    @Override
    public String caption() {
        return this.tabGeneratePoC.caption();
    }

    @Override
    public Component uiComponent() {
        return this.tabGeneratePoC.uiComponent();
    }

    @Override
    public Selection selectedData() {
        return this.tabGeneratePoC.selectedData();
    }

    @Override
    public boolean isModified() {
        return this.tabGeneratePoC.isModified();
    }

}
