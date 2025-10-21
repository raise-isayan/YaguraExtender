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
public class JWSViewTabEditor implements ExtensionProvidedHttpRequestEditor {

    private final JWSViewTab tabJWSView;

    public JWSViewTabEditor(EditorCreationContext editorCreationContext) {
        this.tabJWSView = new JWSViewTab();
    }

    @Override
    public HttpRequest getRequest() {
        HttpRequestResponse http = this.tabJWSView.getHttpRequestResponse();
        return http.request();
    }

    @Override
    public void setRequestResponse(HttpRequestResponse httpRequestResponse) {
        this.tabJWSView.setRequestResponse(httpRequestResponse);
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse httpRequestResponse) {
        return this.tabJWSView.isEnabledFor(httpRequestResponse);
    }

    @Override
    public String caption() {
        return this.tabJWSView.caption();
    }

    @Override
    public Component uiComponent() {
        return this.tabJWSView.uiComponent();
    }

    @Override
    public Selection selectedData() {
        return this.tabJWSView.selectedData();
    }

    @Override
    public boolean isModified() {
        return this.tabJWSView.isModified();
    }

}
