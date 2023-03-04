package yagura.view;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import java.awt.Component;

/**
 *
 * @author isayan
 */
public class GeneratePoCTabEditor implements ExtensionProvidedHttpRequestEditor {

    private final GeneratePoCTab tabGeneratePoC;

    public GeneratePoCTabEditor(EditorCreationContext editorCreationContext) {
        this.tabGeneratePoC = new GeneratePoCTab();
    }

    @Override
    public HttpRequest getRequest() {
        HttpRequestResponse http = this.tabGeneratePoC.getHttpRequestResponse();
        return http.request();
    }

    @Override
    public void setRequestResponse(HttpRequestResponse httpRequestResponse) {
        this.tabGeneratePoC.setRequestResponse(httpRequestResponse);
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse httpRequestResponse) {
        return this.tabGeneratePoC.isEnabledFor(httpRequestResponse);
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
