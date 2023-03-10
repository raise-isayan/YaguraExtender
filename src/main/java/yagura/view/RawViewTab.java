package yagura.view;

import burp.BurpExtension;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedEditor;
import extend.util.external.ExtensionHelper;
import extend.util.external.ThemeUI;
import extension.helpers.HttpMesageHelper;
import extension.helpers.StringUtil;
import java.awt.Component;
import java.awt.Font;
import java.awt.SystemColor;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.SwingWorker;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import yagura.model.UniversalViewProperty;

/**
 *
 * @author isayan
 */
public class RawViewTab extends javax.swing.JPanel implements ExtensionProvidedEditor {
    private final static Logger logger = Logger.getLogger(RawViewTab.class.getName());

    final PropertyChangeListener listener = new PropertyChangeListener() {
        @Override
        public void propertyChange(PropertyChangeEvent evt) {
            ThemeUI.changeStyleTheme(txtURaw);
        }
    };

    private boolean isRequest = false;
    private boolean textModified = false;
    private boolean editable =false;
    private final EditorCreationContext editorCreationContext;
    private HttpRequestResponse httpRequestResponse;

    /**
     * Creates new form RawViewTab
     *
     * @param request
     */
    public RawViewTab(boolean request) {
        this(ExtensionHelper.newEditorCreationContext(ToolType.EXTENSIONS, EditorMode.READ_ONLY), request);
    }

    /**
     * Creates new form RawViewTab
     * @param editorCreationContext
     * @param isResuest
     */
    public RawViewTab(EditorCreationContext editorCreationContext, boolean isResuest) {
        this.isRequest = isResuest;
        this.editorCreationContext = editorCreationContext;
        this.editable = (this.editorCreationContext.editorMode() == EditorMode.READ_ONLY);
        initComponents();
        customizeComponents();
    }

    private final QuickSearchTab quickSearchTab = new QuickSearchTab();

    private org.fife.ui.rtextarea.RTextScrollPane scrollURaw;
    private org.fife.ui.rsyntaxtextarea.RSyntaxTextArea txtURaw;

    private void customizeComponents() {

        /*** UI design start ***/
        this.txtURaw = new org.fife.ui.rsyntaxtextarea.RSyntaxTextArea();
        this.scrollURaw = new org.fife.ui.rtextarea.RTextScrollPane(this.txtURaw);
        this.txtURaw.setWrapStyleWord(false);

        this.txtURaw.setCodeFoldingEnabled(true);
        this.txtURaw.setClearWhitespaceLinesEnabled(true);
        this.txtURaw.setHighlightCurrentLine(true);
        this.txtURaw.setCurrentLineHighlightColor(SystemColor.textHighlight);
        this.txtURaw.setEditable(false);
//        this.txtURaw.setComponentPopupMenu(popup);
//        scrollURaw.setViewportView(txtURaw);

        add(this.scrollURaw, java.awt.BorderLayout.CENTER);

        /*** UI design end ***/
        this.quickSearchTab.setSelectedTextArea(this.txtURaw);
        this.quickSearchTab.getEncodingComboBox().addItemListener(this.encodingItemStateChanged);
        this.txtURaw.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                textModified = true;
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                textModified = true;
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                textModified = true;
            }

        });
        this.txtURaw.setEditable(this.editable);

        this.add(this.quickSearchTab, java.awt.BorderLayout.SOUTH);

        this.listener.propertyChange(null);
        ThemeUI.addPropertyChangeListener(this.listener);
    }

    private final java.awt.event.ItemListener encodingItemStateChanged = new java.awt.event.ItemListener() {
        @Override
        public void itemStateChanged(java.awt.event.ItemEvent evt) {
            String encoding = quickSearchTab.getSelectedEncoding();
            if (encoding != null) {
                setMessageEncoding(encoding);
            }
        }
    };

    /**
     * This method is called from within the constructor to initialize the form. WARNING: Do NOT modify this code. The
     * content of this method is always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        setLayout(new java.awt.BorderLayout());
    }// </editor-fold>//GEN-END:initComponents

    // Variables declaration - do not modify//GEN-BEGIN:variables
    // End of variables declaration//GEN-END:variables

    public void setMessageFont(Font font) {
        this.txtURaw.setFont(font);
        this.quickSearchTab.setMessageFont(font);
    }

    public void setMessageEncoding(String encoding) {
        try {
            if (this.httpRequestResponse == null) {
                return;
            }
            this.txtURaw.setText("");
            SwingWorker swText = new SwingWorker<String, Object>() {
                @Override
                protected String doInBackground() throws Exception {
                    // Raw
                    publish("...");
                    if (isRequest) {
                        return StringUtil.getStringCharset(httpRequestResponse.request().toByteArray().getBytes(), encoding);
                    } else {
                        return StringUtil.getStringCharset(httpRequestResponse.response().toByteArray().getBytes(), encoding);
                    }
                }

                @Override
                protected void process(List<Object> chunks) {
                    txtURaw.setText("Heavy Processing" + StringUtil.repeat("...", chunks.size()));
                }

                @Override
                protected void done() {
                    try {
                        txtURaw.setText(get());
                        txtURaw.setCaretPosition(0);
                        quickSearchTab.clearViewAndSearch();
                        // quickSearchTab.clearView();
                    } catch (InterruptedException ex) {
                        logger.log(Level.SEVERE, ex.getMessage(), ex);
                    } catch (ExecutionException ex) {
                        logger.log(Level.SEVERE, ex.getMessage(), ex);
                    }
                }
            };
            swText.execute();
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }


    public Component getMessageComponent() {
        return this.txtURaw;
    }

    private final static Map<MimeType, String> MIME_MAP = new HashMap<>();

    static {
        MIME_MAP.put(MimeType.CSS, SyntaxConstants.SYNTAX_STYLE_CSS);
        MIME_MAP.put(MimeType.SCRIPT, SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
        MIME_MAP.put(MimeType.HTML, SyntaxConstants.SYNTAX_STYLE_HTML);
        MIME_MAP.put(MimeType.JSON, SyntaxConstants.SYNTAX_STYLE_JSON_WITH_COMMENTS);
        MIME_MAP.put(MimeType.IMAGE_SVG_XML, SyntaxConstants.SYNTAX_STYLE_XML);
        MIME_MAP.put(MimeType.XML, SyntaxConstants.SYNTAX_STYLE_XML);
        MIME_MAP.put(MimeType.YAML, SyntaxConstants.SYNTAX_STYLE_YAML);
    }

    public static String getSyntaxEditingStyle(String mimeType) {
        if (mimeType != null) {
            return MIME_MAP.getOrDefault(mimeType.toLowerCase(), SyntaxConstants.SYNTAX_STYLE_HTML);
        }
        else {
            return SyntaxConstants.SYNTAX_STYLE_HTML;
        }
    }

    public static String getSyntaxEditingStyle(MimeType mimeType) {
        if (mimeType != null) {
            return MIME_MAP.getOrDefault(mimeType, SyntaxConstants.SYNTAX_STYLE_HTML);
        }
        else {
            return SyntaxConstants.SYNTAX_STYLE_HTML;
        }
    }

    public String getSelectedText() {
        return this.txtURaw.getSelectedText();
    }

    public void clearView() {
        this.txtURaw.setText("");
        this.txtURaw.setEditable(false);
        this.quickSearchTab.clearView();
        this.httpRequestResponse = null;
    }

    /**
     * @param lineWrap the lineWrap to set
     */
    public void setLineWrap(boolean lineWrap) {
        this.txtURaw.setLineWrap(lineWrap);
    }


    @Override
    public void setRequestResponse(HttpRequestResponse httpRequestResponse) {
        this.httpRequestResponse = httpRequestResponse;
        if (this.httpRequestResponse == null) {
            this.clearView();
            this.txtURaw.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_HTML);
        } else {
            String guessCharset = null;
            if (this.isRequest) {
                HttpRequest httpRequest = httpRequestResponse.request();
                guessCharset = HttpMesageHelper.getGuessCharset(httpRequest);
            } else {
                HttpResponse httpResponse = httpRequestResponse.response();
                guessCharset = HttpMesageHelper.getGuessCharset(httpResponse);
                MimeType contentType = httpResponse.statedMimeType();
                this.txtURaw.setSyntaxEditingStyle(getSyntaxEditingStyle(contentType));
            }
            if (guessCharset == null) {
                guessCharset = StandardCharsets.ISO_8859_1.name();
            }
            BurpExtension extenderImpl = BurpExtension.getInstance();
            this.quickSearchTab.getEncodingComboBox().removeItemListener(this.encodingItemStateChanged);
            this.quickSearchTab.renewEncodingList(guessCharset, extenderImpl.getSelectEncodingList());

            this.encodingItemStateChanged.itemStateChanged(null);
            this.quickSearchTab.getEncodingComboBox().addItemListener(this.encodingItemStateChanged);

            this.textModified = false;
        }
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse httpRequestResponse) {
        if (httpRequestResponse == null || (this.isRequest && httpRequestResponse.request() == null) || (!this.isRequest && httpRequestResponse.request() == null)) {
            return false;
        }
        try {
            // "This message is too large to display"
            UniversalViewProperty viewProperty = BurpExtension.getInstance().getProperty().getEncodingProperty();
            EnumSet<UniversalViewProperty.UniversalView> view = viewProperty.getMessageView();
            if (!view.contains(UniversalViewProperty.UniversalView.JRAW)) {
                return false;
            }
            HttpRequest httpRequest = httpRequestResponse.request();
            HttpResponse httpResponse = httpRequestResponse.response();

            if ((this.isRequest && httpRequest.toByteArray().length() > viewProperty.getDispayMaxLength()) ||
               (!this.isRequest && httpResponse.toByteArray().length() > viewProperty.getDispayMaxLength())
                && viewProperty.getDispayMaxLength() != 0) {
                return false;
            }
            this.setLineWrap(viewProperty.isLineWrap());
            if (this.isRequest && httpRequest.toByteArray().length() > 0) {
                return true;
            } else if (!this.isRequest && httpResponse.toByteArray().length() > 0) {
                return true;
            }
            return false;
        }
        catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            return false;
        }
    }

    @Override
    public String caption() {
        return "JRaw";
    }

    @Override
    public Component uiComponent() {
        return this;
    }

    @Override
    public Selection selectedData() {
        return null;
    }

    @Override
    public boolean isModified() {
        return this.textModified;
    }

    public HttpRequestResponse getHttpRequestResponse() {
        if (this.httpRequestResponse != null) {
            if (this.textModified) {
                String modifiedText = this.txtURaw.getText();
                String encoding = this.quickSearchTab.getSelectedEncoding();
                if (encoding != null) {
                    try {
                        if (this.isRequest) {
                            HttpRequest httpRequest = HttpRequest.httpRequest(ByteArray.byteArray(StringUtil.getBytesCharset(modifiedText, encoding)));
                            HttpRequestResponse http = HttpRequestResponse.httpRequestResponse(httpRequest, this.httpRequestResponse.response(), this.httpRequestResponse.annotations());
                            return http;
                        }
                        else {
                            HttpResponse httpResponse = HttpResponse.httpResponse(ByteArray.byteArray(StringUtil.getBytesCharset(modifiedText, encoding)));
                            HttpRequestResponse http = HttpRequestResponse.httpRequestResponse(this.httpRequestResponse.request(), httpResponse, this.httpRequestResponse.annotations());
                            return http;
                        }

                    } catch (UnsupportedEncodingException ex) {
                        return null;
                    }
                } else {
                    return this.httpRequestResponse;
                }
            } else {
                return this.httpRequestResponse;
            }
        } else {
            return null;
        }
    }

}
