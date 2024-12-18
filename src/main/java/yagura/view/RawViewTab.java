package yagura.view;

import burp.BurpExtension;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import extension.burp.ExtensionHelper;
import extend.util.external.ThemeUI;
import extension.burp.IBurpMessageTab;
import extension.helpers.HttpRequestWapper;
import extension.helpers.HttpResponseWapper;
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
import java.util.regex.Pattern;
import javax.swing.JPopupMenu;
import javax.swing.SwingWorker;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import yagura.model.SendToMenu;
import yagura.model.SendToMessage;
import yagura.model.UniversalViewProperty;

/**
 *
 * @author isayan
 */
public class RawViewTab extends javax.swing.JPanel implements SendToMessage, IBurpMessageTab {

    private final static Logger logger = Logger.getLogger(RawViewTab.class.getName());

    final PropertyChangeListener listener = new PropertyChangeListener() {
        @Override
        public void propertyChange(PropertyChangeEvent evt) {
            ThemeUI.applyStyleTheme(txtURaw);
        }
    };

    private boolean isRequest = false;
    private boolean textModified = false;
    private boolean editable = false;
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
     *
     * @param editorCreationContext
     * @param isResuest
     */
    public RawViewTab(EditorCreationContext editorCreationContext, boolean isResuest) {
        this.isRequest = isResuest;
        this.editorCreationContext = editorCreationContext;
        this.editable = !(this.editorCreationContext.editorMode() == EditorMode.READ_ONLY);
        initComponents();
        customizeComponents();
    }

    private final QuickSearchTab quickSearchTab = new QuickSearchTab();

    private org.fife.ui.rtextarea.RTextScrollPane scrollURaw;
    private org.fife.ui.rsyntaxtextarea.RSyntaxTextArea txtURaw;

    private void customizeComponents() {

        /**
         * * UI design start **
         */
        this.txtURaw = new org.fife.ui.rsyntaxtextarea.RSyntaxTextArea();
        this.scrollURaw = new org.fife.ui.rtextarea.RTextScrollPane(this.txtURaw);
        this.txtURaw.setWrapStyleWord(false);

        this.txtURaw.setCodeFoldingEnabled(true);
        this.txtURaw.setClearWhitespaceLinesEnabled(true);
        this.txtURaw.setHighlightCurrentLine(true);
        this.txtURaw.setCurrentLineHighlightColor(SystemColor.textHighlight);
        this.txtURaw.setEditable(this.editable);
        this.add(this.scrollURaw, java.awt.BorderLayout.CENTER);

        /**
         * * UI design end **
         */
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

        BurpExtension extenderImpl = BurpExtension.getInstance();
        JPopupMenu popupSendTo = this.txtURaw.getPopupMenu();
        popupSendTo.addSeparator();
        SendToMenu sendToMenu = extenderImpl.getSendToMenu();
        sendToMenu.appendSendToMenu(popupSendTo, this, sendToMenu.getContextMenu());
        this.txtURaw.setPopupMenu(popupSendTo);

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
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
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
                    } catch (InterruptedException | ExecutionException ex) {
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
        MIME_MAP.put(MimeType.PLAIN_TEXT, SyntaxConstants.SYNTAX_STYLE_NONE);
    }

    public static String getSyntaxEditingStyle(String mimeType) {
        String style = SyntaxConstants.SYNTAX_STYLE_HTML;
        if (mimeType != null) {
            style = MIME_MAP.getOrDefault(mimeType.toLowerCase(), SyntaxConstants.SYNTAX_STYLE_HTML);
        }
        return style;
    }

    public static String getSyntaxEditingStyle(MimeType mimeType) {
        String style = SyntaxConstants.SYNTAX_STYLE_HTML;
        if (mimeType != null) {
            style = MIME_MAP.getOrDefault(mimeType, SyntaxConstants.SYNTAX_STYLE_HTML);
        }
        return style;
    }

    public static String getSyntaxEditingStyle(ContentType contentType) {
        String style = SyntaxConstants.SYNTAX_STYLE_HTML;
        if (contentType != null) {
            switch (contentType) {
            case JSON:
                style = SyntaxConstants.SYNTAX_STYLE_JSON;
                break;
            case XML:
                style = SyntaxConstants.SYNTAX_STYLE_XML;
                break;
            default:
                break;
            }
        }
        return style;
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
        final BurpExtension extenderImpl = BurpExtension.getInstance();
        this.httpRequestResponse = httpRequestResponse;
        if (this.httpRequestResponse == null) {
            this.clearView();
            this.txtURaw.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_HTML);
        } else {
            String guessCharset = StandardCharsets.UTF_8.name();
            if (this.isRequest) {
                HttpRequestWapper wrapRequest = new HttpRequestWapper(httpRequestResponse.request());
                guessCharset = wrapRequest.getGuessCharset(StandardCharsets.UTF_8.name());
                ContentType contentType = wrapRequest.contentType();
                this.txtURaw.setSyntaxEditingStyle(getSyntaxEditingStyle(contentType));
            } else {
                HttpResponseWapper wrapResponse = new HttpResponseWapper(httpRequestResponse.response());
                guessCharset = wrapResponse.getGuessCharset(StandardCharsets.UTF_8.name());
                MimeType contentType = wrapResponse.statedMimeType();
                this.txtURaw.setSyntaxEditingStyle(getSyntaxEditingStyle(contentType));
            }

            this.quickSearchTab.getEncodingComboBox().removeItemListener(this.encodingItemStateChanged);
            this.quickSearchTab.renewEncodingList(guessCharset, extenderImpl.getSelectEncodingList());

            this.encodingItemStateChanged.itemStateChanged(null);
            this.quickSearchTab.getEncodingComboBox().addItemListener(this.encodingItemStateChanged);

//            this.setMessageEncoding(guessCharset);
            this.textModified = false;
        }
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse httpRequestResponse) {
        final BurpExtension extenderImpl = BurpExtension.getInstance();
        if (httpRequestResponse == null || (this.isRequest && httpRequestResponse.request() == null) || (!this.isRequest && !httpRequestResponse.hasResponse())) {
            return false;
        }

        try {
            // "This message is too large to display"
            UniversalViewProperty viewProperty = extenderImpl.getProperty().getUniversalViewProperty();
            EnumSet<UniversalViewProperty.MessageView> view = viewProperty.getMessageView();
            if (!view.contains(UniversalViewProperty.MessageView.JRAW)) {
                return false;
            }

            // Burp v2023.4.1 以降の謎挙動に対応
            if ((httpRequestResponse.request() != null && httpRequestResponse.request().toByteArray().length() == 0 && httpRequestResponse.response() == null)
                    || (httpRequestResponse.response() != null && httpRequestResponse.response().toByteArray().length() == 0)) {
                return true;
            }

            HttpRequest httpRequest = httpRequestResponse.request();
            HttpResponse httpResponse = httpRequestResponse.response();

            if ((this.isRequest && httpRequest.toByteArray().length() > viewProperty.getDispayMaxLength())
                    || (!this.isRequest && httpResponse.toByteArray().length() > viewProperty.getDispayMaxLength())
                    && viewProperty.getDispayMaxLength() != 0) {
                return false;
            }
            this.setLineWrap(viewProperty.isLineWrap());
            if (this.isRequest && httpRequest.toByteArray().length() > 0) {
                return true;
            } else if (!this.isRequest && httpResponse.toByteArray().length() > 0) {
                return true;
            }
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return false;
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

    @Override
    public HttpRequestResponse getHttpRequestResponse() {
        if (this.httpRequestResponse != null) {
            if (this.textModified) {
                String modifiedText = this.txtURaw.getText();
                String encoding = this.quickSearchTab.getSelectedEncoding();
                if (encoding != null) {
                    try {
                        if (this.isRequest) {
                            HttpRequest httpRequest = ExtensionHelper.httpRequest(this.httpRequestResponse.httpService(), ByteArray.byteArray(StringUtil.getBytesCharset(modifiedText, encoding)));
                            HttpRequestResponse http = HttpRequestResponse.httpRequestResponse(httpRequest, this.httpRequestResponse.response(), this.httpRequestResponse.annotations());
                            return http;
                        } else {
                            HttpResponse httpResponse = HttpResponse.httpResponse(ByteArray.byteArray(StringUtil.getBytesCharset(modifiedText, encoding)));
                            HttpRequestResponse http = HttpRequestResponse.httpRequestResponse(this.httpRequestResponse.request(), httpResponse, this.httpRequestResponse.annotations());
                            return http;
                        }

                    } catch (UnsupportedEncodingException ex) {
                        logger.log(Level.SEVERE, ex.getMessage(), ex);
                    }
                } else {
                    return this.httpRequestResponse;
                }
            } else {
                return this.httpRequestResponse;
            }
        }
        return null;
    }

    /* impelements SendToMessage */
    @Override
    public String getSelectedText() {
        return this.txtURaw.getSelectedText();
    }

    @Override
    public List<HttpRequestResponse> getSelectedMessages() {
        return List.of(this.getHttpRequestResponse());
    }

    @Override
    public boolean isExtendVisible() {
        return false;
    }

    protected final static Pattern CONTENT_CHARSET = Pattern.compile("(\\s*charset=[\"\']?([\\w_-]+)[\"\']?)", Pattern.MULTILINE);

}
