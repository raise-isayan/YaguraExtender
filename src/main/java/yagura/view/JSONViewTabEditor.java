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
public class JSONViewTabEditor implements ExtensionProvidedHttpRequestEditor, ExtensionProvidedHttpResponseEditor {

    private final JSONViewTab tabJSONView;

    public JSONViewTabEditor(EditorCreationContext editorCreationContext, boolean isResuest) {
        this.tabJSONView = new JSONViewTab(editorCreationContext, isResuest) {
            @Override
            public boolean isJsonp() {
                return JSONViewTabEditor.this.isJsonp();
            }
        };
    }

    @Override
    public HttpRequest getRequest() {
        HttpRequestResponse http = this.tabJSONView.getHttpRequestResponse();
        return http.request();
    }

    @Override
    public HttpResponse getResponse() {
        HttpRequestResponse http = this.tabJSONView.getHttpRequestResponse();
        return http.response();
    }

    @Override
    public void setRequestResponse(HttpRequestResponse httpRequestResponse) {
        this.tabJSONView.setRequestResponse(httpRequestResponse);
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse httpRequestResponse) {
        return this.tabJSONView.isEnabledFor(httpRequestResponse);
    }

    @Override
    public String caption() {
        return this.tabJSONView.caption();
    }

    @Override
    public Component uiComponent() {
        return this.tabJSONView.uiComponent();
    }

    @Override
    public Selection selectedData() {
        return this.tabJSONView.selectedData();
    }

    @Override
    public boolean isModified() {
        return this.tabJSONView.isModified();
    }

    public boolean isJsonp() {
        return false;
    }

}
