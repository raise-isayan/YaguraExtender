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
public class HtmlCommetViewTabEditor implements ExtensionProvidedHttpResponseEditor {
    private final HtmlCommetViewTab tabHtmlCommetView;

    public HtmlCommetViewTabEditor(EditorCreationContext editorCreationContext) {
        this.tabHtmlCommetView = new HtmlCommetViewTab();
    }

    @Override
    public HttpResponse getResponse() {
        HttpRequestResponse http = this.tabHtmlCommetView.getHttpRequestResponse();
        return http.response();
    }

    @Override
    public void setRequestResponse(HttpRequestResponse httpRequestResponse) {
        this.tabHtmlCommetView.setRequestResponse(httpRequestResponse);
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse httpRequestResponse) {
        return this.tabHtmlCommetView.isEnabledFor(httpRequestResponse);
    }

    @Override
    public String caption() {
        return this.tabHtmlCommetView.caption();
    }

    @Override
    public Component uiComponent() {
        return this.tabHtmlCommetView.uiComponent();
    }

    @Override
    public Selection selectedData() {
        return this.tabHtmlCommetView.selectedData();
    }

    @Override
    public boolean isModified() {
        return this.tabHtmlCommetView.isModified();
    }

}
