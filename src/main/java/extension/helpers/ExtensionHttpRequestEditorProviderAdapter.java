/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package extension.helpers;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.ExtensionHttpRequestEditorProvider;

/**
 *
 * @author isayan
 */
public class ExtensionHttpRequestEditorProviderAdapter implements ExtensionHttpRequestEditorProvider {

    @Override
    public ExtensionHttpRequestEditor provideHttpRequestEditor(HttpRequestResponse hrr, EditorMode em) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

}
