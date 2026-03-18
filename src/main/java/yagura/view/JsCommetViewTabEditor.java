package yagura.view;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import java.awt.Component;

/**
 *
 * @author isayan
 */
public class JsCommetViewTabEditor implements ExtensionProvidedHttpResponseEditor {

    private final JsCommetViewTab tabJsCommetView;

    public JsCommetViewTabEditor(EditorCreationContext editorCreationContext) {
        this.tabJsCommetView = new JsCommetViewTab();
    }

    @Override
    public HttpResponse getResponse() {
        HttpRequestResponse http = this.tabJsCommetView.getHttpRequestResponse();
        return http.response();
    }

    @Override
    public void setRequestResponse(HttpRequestResponse httpRequestResponse) {
        this.tabJsCommetView.setRequestResponse(httpRequestResponse);
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse httpRequestResponse) {
        return this.tabJsCommetView.isEnabledFor(httpRequestResponse);
    }

    @Override
    public String caption() {
        return this.tabJsCommetView.caption();
    }

    @Override
    public Component uiComponent() {
        return this.tabJsCommetView.uiComponent();
    }

    @Override
    public Selection selectedData() {
        return this.tabJsCommetView.selectedData();
    }

    @Override
    public boolean isModified() {
        return this.tabJsCommetView.isModified();
    }

}
