package yagura.view;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import java.awt.Component;

/**
 *
 * @author isayan
 */
public class RawViewTabEditor implements ExtensionProvidedHttpRequestEditor, ExtensionProvidedHttpResponseEditor {

    private final RawViewTab tabRaw;

    public RawViewTabEditor(EditorCreationContext editorCreationContext, boolean isResuest) {
        this.tabRaw = new RawViewTab(editorCreationContext, isResuest);
    }

    @Override
    public HttpRequest getRequest() {
        HttpRequestResponse http = this.tabRaw.getHttpRequestResponse();
        return http.request();
    }

    @Override
    public HttpResponse getResponse() {
        HttpRequestResponse http = this.tabRaw.getHttpRequestResponse();
        return http.response();
    }

    @Override
    public void setRequestResponse(HttpRequestResponse httpRequestResponse) {
        this.tabRaw.setRequestResponse(httpRequestResponse);
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse httpRequestResponse) {
        return this.tabRaw.isEnabledFor(httpRequestResponse);
    }

    @Override
    public String caption() {
        return this.tabRaw.caption();
    }

    @Override
    public Component uiComponent() {
        return this.tabRaw.uiComponent();
    }

    @Override
    public Selection selectedData() {
        return this.tabRaw.selectedData();
    }

    @Override
    public boolean isModified() {
        return this.tabRaw.isModified();
    }

}
