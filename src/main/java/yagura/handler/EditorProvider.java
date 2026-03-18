package yagura.handler;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedWebSocketMessageEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;
import burp.api.montoya.ui.editor.extension.WebSocketMessageEditorProvider;
import yagura.view.GeneratePoCTabEditor;
import yagura.view.GenerateWebsocktPoCEditor;
import yagura.view.HtmlCommetViewTabEditor;
import yagura.view.JSONViewTabEditor;
import yagura.view.JWSViewTabEditor;
import yagura.view.JsCommetViewTabEditor;
import yagura.view.ParamsViewTabEditor;
import yagura.view.RawViewTabEditor;
import yagura.view.ViewStateTabEditor;

/**
 *
 * @author isayan
 */
public class EditorProvider {

    private final MontoyaApi api;

    public EditorProvider(MontoyaApi api) {
        this.api = api;
        this.api.userInterface().registerHttpRequestEditorProvider(this.requestRawTab);
        this.api.userInterface().registerHttpResponseEditorProvider(this.responseRawTab);
        this.api.userInterface().registerHttpRequestEditorProvider(this.requestParamsTab);
        this.api.userInterface().registerHttpRequestEditorProvider(this.requestGeneratePoCTab);
        this.api.userInterface().registerHttpRequestEditorProvider(this.requestViewStateTab);
        this.api.userInterface().registerHttpResponseEditorProvider(this.responseHtmlCommentViewTab);
        this.api.userInterface().registerHttpResponseEditorProvider(this.responseJsCommentViewTab);
        this.api.userInterface().registerHttpRequestEditorProvider(this.requestJSONTab);
        this.api.userInterface().registerHttpResponseEditorProvider(this.responseJSONTab);
        this.api.userInterface().registerHttpResponseEditorProvider(this.responseJSONPTab);
        this.api.userInterface().registerHttpRequestEditorProvider(this.requestJwtViewTab);
        this.api.userInterface().registerWebSocketMessageEditorProvider(this.requestGenerateWebSocketPoCTab);
    }

    private final HttpRequestEditorProvider requestRawTab = new HttpRequestEditorProvider() {

        @Override
        public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext editorCreationContext) {
            final RawViewTabEditor tab = new RawViewTabEditor(editorCreationContext, true);
            return tab;
        }
    };

    private final HttpResponseEditorProvider responseRawTab = new HttpResponseEditorProvider() {

        @Override
        public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext editorCreationContext) {
            final RawViewTabEditor tab = new RawViewTabEditor(editorCreationContext, false);
            return tab;
        }
    };

    private final HttpRequestEditorProvider requestParamsTab = new HttpRequestEditorProvider() {

        @Override
        public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext editorCreationContext) {
            final ParamsViewTabEditor tab = new ParamsViewTabEditor(editorCreationContext);
            return tab;
        }
    };

    private final HttpRequestEditorProvider requestJSONTab = new HttpRequestEditorProvider() {
        @Override
        public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext editorCreationContext) {
            final JSONViewTabEditor tab = new JSONViewTabEditor(editorCreationContext, true);
            return tab;
        }
    };

    private final HttpResponseEditorProvider responseJSONTab = new HttpResponseEditorProvider() {

        @Override
        public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext editorCreationContext) {
            final JSONViewTabEditor tab = new JSONViewTabEditor(editorCreationContext, false);
            return tab;
        }
    };

    private final HttpResponseEditorProvider responseJSONPTab = new HttpResponseEditorProvider() {

        @Override
        public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext editorCreationContext) {
            final JSONViewTabEditor tab = new JSONViewTabEditor(editorCreationContext, false) {
                @Override
                public boolean isJsonp() {
                    return true;
                }
            };
            return tab;
        }
    };

    private final HttpResponseEditorProvider responseHtmlCommentViewTab = new HttpResponseEditorProvider() {

        @Override
        public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext editorCreationContext) {
            final HtmlCommetViewTabEditor tab = new HtmlCommetViewTabEditor(editorCreationContext);
            return tab;
        }
    };

    private final HttpResponseEditorProvider responseJsCommentViewTab = new HttpResponseEditorProvider() {

        @Override
        public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext editorCreationContext) {
            final JsCommetViewTabEditor tab = new JsCommetViewTabEditor(editorCreationContext);
            return tab;
        }
    };

    private final HttpRequestEditorProvider requestViewStateTab = new HttpRequestEditorProvider() {

        @Override
        public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext editorCreationContext) {
            final ViewStateTabEditor tab = new ViewStateTabEditor(editorCreationContext);
            return tab;
        }
    };

    private final HttpRequestEditorProvider requestJwtViewTab = new HttpRequestEditorProvider() {

        @Override
        public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext editorCreationContext) {
            final JWSViewTabEditor tab = new JWSViewTabEditor(editorCreationContext);
            return tab;
        }
    };

    private final HttpRequestEditorProvider requestGeneratePoCTab = new HttpRequestEditorProvider() {

        @Override
        public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext editorCreationContext) {
            final GeneratePoCTabEditor tab = new GeneratePoCTabEditor(editorCreationContext);
            return tab;
        }
    };

    private final WebSocketMessageEditorProvider requestGenerateWebSocketPoCTab = new WebSocketMessageEditorProvider() {
        @Override
        public ExtensionProvidedWebSocketMessageEditor provideMessageEditor(EditorCreationContext editorCreationContext) {
            final GenerateWebsocktPoCEditor tab = new GenerateWebsocktPoCEditor(editorCreationContext);
            return tab;
        }
    };

}
