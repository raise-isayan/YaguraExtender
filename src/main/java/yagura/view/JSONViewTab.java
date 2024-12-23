package yagura.view;

import burp.BurpExtension;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.ui.Selection;
import extension.burp.ExtensionHelper;
import extend.util.external.FormatUtil;
import extension.burp.IBurpMessageTab;
import extension.helpers.HttpRequestWapper;
import extension.helpers.HttpResponseWapper;
import extension.helpers.StringUtil;
import java.awt.Component;
import java.awt.Font;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.EnumSet;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JPopupMenu;
import javax.swing.text.JTextComponent;
import yagura.model.QuickSearchEvent;
import yagura.model.QuickSearchListener;
import yagura.model.SendToMenu;
import yagura.model.SendToMessage;
import yagura.model.UniversalViewProperty;

/**
 *
 * @author isayan
 */
public class JSONViewTab extends javax.swing.JPanel implements SendToMessage, IBurpMessageTab {

    private final static Logger logger = Logger.getLogger(JSONViewTab.class.getName());

    private final boolean isRequest;
    private boolean textModified = false;
    private boolean editable = false;
    private final EditorCreationContext editorCreationContext;
    private HttpRequestResponse httpRequestResponse;

    public JSONViewTab(boolean request) {
        this(ExtensionHelper.newEditorCreationContext(ToolType.EXTENSIONS, EditorMode.READ_ONLY), request);
    }

    /**
     * Creates new form JSONView
     *
     * @param editorCreationContext
     * @param isResuest
     */
    public JSONViewTab(EditorCreationContext editorCreationContext, boolean isResuest) {
        this.isRequest = isResuest;
        this.editorCreationContext = editorCreationContext;
        this.editable = !(this.editorCreationContext.editorMode() == EditorMode.READ_ONLY);
        initComponents();
        customizeComponents();
    }

    private JSONView jsonView;
    private final QuickSearchTab quickSearchTab = new QuickSearchTab();

    @SuppressWarnings("unchecked")
    private void customizeComponents() {
        this.jsonView = new JSONView(isJsonp());
        this.add(jsonView, java.awt.BorderLayout.CENTER);

        org.fife.ui.rsyntaxtextarea.RSyntaxTextArea txtJSON = (org.fife.ui.rsyntaxtextarea.RSyntaxTextArea) this.jsonView.getTextArea();
        this.quickSearchTab.setSelectedTextArea(txtJSON);
        this.quickSearchTab.getEncodingComboBox().addItemListener(encodingItemStateChanged);
        this.quickSearchTab.addQuickSearchListener(quickSerchStateChanged);

        BurpExtension extenderImpl = BurpExtension.getInstance();
        JPopupMenu popupMenu = txtJSON.getPopupMenu();
        popupMenu.addSeparator();
        SendToMenu sendToMenu = extenderImpl.getSendToMenu();
        sendToMenu.appendSendToMenu(popupMenu, this, sendToMenu.getContextMenu());
        txtJSON.setPopupMenu(popupMenu);

        this.add(this.quickSearchTab, java.awt.BorderLayout.SOUTH);
    }

    public boolean isJsonp() {
        return false;
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

    private final QuickSearchListener quickSerchStateChanged = new QuickSearchListener() {

        @Override
        public void quickBackPerformed(QuickSearchEvent evt) {

        }

        @Override
        public void quickForwardPerformed(QuickSearchEvent evt) {

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
    public void setMessageEncoding(String encoding) {
        try {
            if (this.httpRequestResponse != null) {
                if (this.isRequest) {
                    String msg = StringUtil.getStringCharset(this.httpRequestResponse.request().body().getBytes(), encoding);
                    this.jsonView.setMessage(msg);
                } else {
                    String msg = StringUtil.getStringCharset(this.httpRequestResponse.response().body().getBytes(), encoding);
                    this.jsonView.setMessage(msg);
                }

            } else {
                this.jsonView.setMessage(null);
            }
            this.quickSearchTab.clearViewAndSearch();
        } catch (UnsupportedEncodingException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    public void setMessageFont(Font font) {
        this.jsonView.setMessageFont(font);
        this.quickSearchTab.setMessageFont(font);
    }

    protected JTextComponent getSelectedTextArea() {
        return this.jsonView.getTextArea();
    }

    public boolean isEnabledJson(HttpRequestResponse httpRequestResponse, boolean isMessageRequest) {
        BurpExtension extenderImpl = BurpExtension.getInstance();
        UniversalViewProperty viewProperty = extenderImpl.getProperty().getUniversalViewProperty();
        EnumSet<UniversalViewProperty.MessageView> view = viewProperty.getMessageView();
        if (!view.contains(UniversalViewProperty.MessageView.JSON)) {
            return false;
        }
        // Burp v2023.4.1 以降の謎挙動に対応
        if ((httpRequestResponse.request() != null && httpRequestResponse.request().toByteArray().length() == 0 && httpRequestResponse.response() == null)
                || (httpRequestResponse.response() != null && httpRequestResponse.response().toByteArray().length() == 0)) {
            return true;
        }
        HttpRequest httpRequest = httpRequestResponse.request();
        HttpResponse httpResponse = httpRequestResponse.response();

        if ((isMessageRequest && httpRequest.body().length() > viewProperty.getDispayMaxLength()
                || (!isMessageRequest && httpResponse.body().length() > viewProperty.getDispayMaxLength()))
                && viewProperty.getDispayMaxLength() != 0) {
            return false;
        }

        this.setLineWrap(viewProperty.isLineWrap());
        boolean mimeJsonType = false;
        byte[] body = new byte[0];

        if (this.isRequest && isMessageRequest) {
            ContentType contentType = httpRequest.contentType();
            mimeJsonType = (contentType == ContentType.JSON);
            body = httpRequest.body().getBytes();
        } else if (!this.isRequest && !isMessageRequest) {
            MimeType mimeType = httpResponse.statedMimeType();
            mimeJsonType = (mimeType == MimeType.JSON);
            body = httpResponse.body().getBytes();
        }
        if (body.length > 0 && mimeJsonType) {
            return FormatUtil.isJson(StringUtil.getBytesRawString(body));
        } else {
            return FormatUtil.isJson(StringUtil.getBytesRawString(body));
        }
    }

    public boolean isEnabledJsonp(HttpRequestResponse httpRequestResponse, boolean isMessageRequest) {
        BurpExtension extenderImpl = BurpExtension.getInstance();
        UniversalViewProperty viewProperty = extenderImpl.getProperty().getUniversalViewProperty();
        EnumSet<UniversalViewProperty.MessageView> view = extenderImpl.getProperty().getUniversalViewProperty().getMessageView();
        if (!view.contains(UniversalViewProperty.MessageView.JSONP)) {
            return false;
        }
        // Burp v2023.4.1 以降の謎挙動に対応
        if ((httpRequestResponse.request() != null && httpRequestResponse.request().toByteArray().length() == 0 && httpRequestResponse.response() == null)
                || (httpRequestResponse.response() != null && httpRequestResponse.response().toByteArray().length() == 0)) {
            return true;
        }
        HttpRequest httpRequest = httpRequestResponse.request();
        HttpResponse httpResponse = httpRequestResponse.response();

        if ((isMessageRequest && httpRequest.toByteArray().length() > viewProperty.getDispayMaxLength()
                || (!isMessageRequest && httpResponse.toByteArray().length() > viewProperty.getDispayMaxLength()))
                && viewProperty.getDispayMaxLength() != 0) {
            return false;
        }

        byte[] body = new byte[0];
        if (this.isRequest && isMessageRequest) {
            body = httpRequest.body().getBytes();
        } else if (!this.isRequest && !isMessageRequest) {
            body = httpResponse.body().getBytes();
        }
        return FormatUtil.isJsonp(StringUtil.getBytesRawString(body));
    }

    @Override
    public boolean isModified() {
        return false;
    }

    public void clearView() {
        this.quickSearchTab.clearView();
    }

    /**
     * @return the lineWrap
     */
    public boolean isLineWrap() {
        return this.jsonView.isLineWrap();
    }

    /**
     * @param lineWrap the lineWrap to set
     */
    public void setLineWrap(boolean lineWrap) {
        this.jsonView.setLineWrap(lineWrap);
    }

    @Override
    public HttpRequestResponse getHttpRequestResponse() {
        return this.httpRequestResponse;
    }

    @Override
    public void setRequestResponse(HttpRequestResponse httpRequestResponse) {
        final BurpExtension extenderImpl = BurpExtension.getInstance();
        this.httpRequestResponse = httpRequestResponse;
        String guessCharset = StandardCharsets.UTF_8.name();
        if (this.isRequest) {
            HttpRequestWapper wrapRequest = new HttpRequestWapper(httpRequestResponse.request());
            guessCharset = wrapRequest.getGuessCharset(StandardCharsets.UTF_8.name());
        } else {
            HttpResponseWapper wrapResponse = new HttpResponseWapper(httpRequestResponse.response());
            guessCharset = wrapResponse.getGuessCharset(StandardCharsets.UTF_8.name());
        }

        this.quickSearchTab.getEncodingComboBox().removeItemListener(encodingItemStateChanged);
        this.quickSearchTab.renewEncodingList(guessCharset, extenderImpl.getSelectEncodingList());
        encodingItemStateChanged.itemStateChanged(null);
        this.quickSearchTab.getEncodingComboBox().addItemListener(encodingItemStateChanged);

//            this.setMessageEncoding(guessCharset);
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse httpRequestResponse) {
        if (httpRequestResponse == null) {
            return false;
        }
        try {
            if (this.isJsonp()) {
                return isEnabledJsonp(httpRequestResponse, this.isRequest);
            } else {
                return isEnabledJson(httpRequestResponse, this.isRequest);
            }
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            return false;
        }
    }

    @Override
    public String caption() {
        if (this.isJsonp()) {
            return "JSONP";
        } else {
            return "JSON";
        }
    }

    @Override
    public Component uiComponent() {
        return this;
    }

    @Override
    public Selection selectedData() {
        return null;
    }

    /* impelements SendToMessage */
    @Override
    public String getSelectedText() {
        JTextComponent area = this.getSelectedTextArea();
        return area.getSelectedText();
    }

    @Override
    public boolean isExtendVisible() {
        return false;
    }

    @Override
    public List<HttpRequestResponse> getSelectedMessages() {
        return List.of(this.getHttpRequestResponse());
    }

}
