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
public class JWTViewTabEditor implements ExtensionProvidedHttpRequestEditor {
    private final JWTViewTab tabJWTView;

    public JWTViewTabEditor(EditorCreationContext editorCreationContext) {
        this.tabJWTView = new JWTViewTab();
    }

    @Override
    public HttpRequest getRequest() {
        HttpRequestResponse http = this.tabJWTView.getHttpRequestResponse();
        return http.request();
    }

    @Override
    public void setRequestResponse(HttpRequestResponse httpRequestResponse) {
        this.tabJWTView.setRequestResponse(httpRequestResponse);
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse httpRequestResponse) {
        return this.tabJWTView.isEnabledFor(httpRequestResponse);
    }

    @Override
    public String caption() {
        return this.tabJWTView.caption();
    }

    @Override
    public Component uiComponent() {
        return this.tabJWTView.uiComponent();
    }

    @Override
    public Selection selectedData() {
        return this.tabJWTView.selectedData();
    }

    @Override
    public boolean isModified() {
        return this.tabJWTView.isModified();
    }

}
