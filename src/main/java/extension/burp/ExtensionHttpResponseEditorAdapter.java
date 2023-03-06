package extension.burp;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import java.awt.Component;

/**
 *
 * @author isayan
 */
public abstract class ExtensionHttpResponseEditorAdapter implements ExtensionProvidedHttpResponseEditor {

    private final ExtensionProvidedHttpResponseEditor editor;

    public ExtensionHttpResponseEditorAdapter(ExtensionProvidedHttpResponseEditor editor) {
        this.editor = editor;
    }

    @Override
    public void setRequestResponse(HttpRequestResponse httpRequestResponse) {
        this.editor.setRequestResponse(httpRequestResponse);
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse httpRequestResponse) {
        return this.editor.isEnabledFor(httpRequestResponse);
    }

    @Override
    public String caption() {
        return this.editor.caption();
    }

    @Override
    public Component uiComponent() {
        return this.editor.uiComponent();
    }

    @Override
    public Selection selectedData() {
        return this.editor.selectedData();
    }

    @Override
    public boolean isModified() {
        return this.editor.isModified();
    }

}
