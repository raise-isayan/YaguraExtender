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
public class ParamsViewTabEditor implements ExtensionProvidedHttpRequestEditor {

    private final ParamsViewTab tabParamsView;

    public ParamsViewTabEditor(EditorCreationContext editorCreationContext) {
        this.tabParamsView = new ParamsViewTab(editorCreationContext);
    }

    @Override
    public HttpRequest getRequest() {
        HttpRequestResponse http = this.tabParamsView.getHttpRequestResponse();
        return http.request();
    }

    @Override
    public void setRequestResponse(HttpRequestResponse httpRequestResponse) {
        this.tabParamsView.setRequestResponse(httpRequestResponse);
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse httpRequestResponse) {
        return this.tabParamsView.isEnabledFor(httpRequestResponse);
    }

    @Override
    public String caption() {
        return this.tabParamsView.caption();
    }

    @Override
    public Component uiComponent() {
        return this.tabParamsView.uiComponent();
    }

    @Override
    public Selection selectedData() {
        return this.tabParamsView.selectedData();
    }

    @Override
    public boolean isModified() {
        return this.tabParamsView.isModified();
    }

}
