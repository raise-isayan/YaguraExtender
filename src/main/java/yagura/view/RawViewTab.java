package yagura.view;

import burp.BurpExtender;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import extend.util.external.ThemeUI;
import extension.helpers.HttpMessage;
import extension.helpers.HttpRequest;
import extension.helpers.HttpResponse;
import extension.helpers.StringUtil;
import java.awt.Component;
import java.awt.Font;
import java.awt.SystemColor;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.SwingWorker;
import javax.swing.UIManager;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import yagura.model.UniversalViewProperty;

/**
 *
 * @author isayan
 */
public class RawViewTab extends javax.swing.JPanel implements IMessageEditorTab {
    private final static Logger logger = Logger.getLogger(RawViewTab.class.getName());

    final PropertyChangeListener listener = new PropertyChangeListener() {
        @Override
        public void propertyChange(PropertyChangeEvent evt) {
            ThemeUI.changeStyleTheme(txtURaw);        
        }
    };
               
    private boolean request = false;
    private boolean textModified = false;
    private boolean editable = false;
    private IMessageEditorController controller = null;

//    private final EditorKit htmlStyleEditorKit = new StyledEditorKit() {
//        @Override
//        public Document createDefaultDocument() {
//            return new HTMLSyntaxDocument();
//        }
//    };

    /**
     * Creates new form RawViewTab
     *
     * @param request
     */
    public RawViewTab(boolean request) {
        this.request = request;
        initComponents();
        customizeComponents();
    }

    /**
     * Creates new form RawViewTab
     */
    public RawViewTab(IMessageEditorController controller, boolean editable, boolean isResuest) {
        this.request = isResuest;
        this.controller = controller;
        //this.editable = editable;
        this.editable = false;
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

//        this.txtRaw.setEditorKitForContentType("text/html", this.htmlStyleEditorKit);
//        this.txtRaw.setEditorKitForContentType("application/xhtml+xml", this.htmlStyleEditorKit);
//        this.txtRaw.setEditorKitForContentType("text/xml", this.htmlStyleEditorKit);
//        this.txtRaw.setEditorKitForContentType("application/xml", this.htmlStyleEditorKit);
//        this.txtRaw.setEditorKitForContentType("image/svg+xml", this.htmlStyleEditorKit);
//        this.txtRaw.setContentType("text/html");

        this.add(this.quickSearchTab, java.awt.BorderLayout.SOUTH);
    
        this.listener.propertyChange(null);
        UIManager.addPropertyChangeListener(listener);                
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
            if (this.content == null) {
                return;
            }
            this.txtURaw.setText("");
            if (this.content != null) {
//                txtURaw.setText(StringUtil.getStringCharset(content, encoding));
//                txtURaw.setCaretPosition(0);
//                quickSearchTab.clearViewAndSearch();

                SwingWorker swText = new SwingWorker<String, Object>() {
                    @Override
                    protected String doInBackground() throws Exception {
                        // Raw
                        publish("...");
                        return StringUtil.getStringCharset(content, encoding);
                    }

                    protected void process(List<Object> chunks) {
                        txtURaw.setText("Heavy Processing" + StringUtil.repeat("...", chunks.size()));
                    }

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
            }
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    @Override
    public String getTabCaption() {
        return "JRaw";
    }

    @Override
    public Component getUiComponent() {
        return this;
    }

    public Component getMessageComponent() {
        return this.txtURaw;
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest) {
        if (content == null || content.length == 0) {
            return false;
        }
        // "This message is too large to display"
        UniversalViewProperty viewProperty = BurpExtender.getInstance().getProperty().getEncodingProperty();
        EnumSet<UniversalViewProperty.UniversalView> view = viewProperty.getMessageView();
        if (!view.contains(UniversalViewProperty.UniversalView.JRAW)) {
            return false;
        }
        if (content.length > viewProperty.getDispayMaxLength() && viewProperty.getDispayMaxLength() != 0) {
            return false;
        }
        this.setLineWrap(viewProperty.isLineWrap());
        if (this.request && isRequest && content.length > 0) {
            return true;
        } else if (!this.request && !isRequest && content.length > 0) {
            return true;
        }
        return false;
    }

    private final static Map<String, String> CODE_MAP = new HashMap<>();

    static {
        CODE_MAP.put("text/css", SyntaxConstants.SYNTAX_STYLE_CSS);
        CODE_MAP.put("tex/javascript", SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
        CODE_MAP.put("application/javascript", SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
        CODE_MAP.put("application/x-javascript", SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
        CODE_MAP.put("text/html", SyntaxConstants.SYNTAX_STYLE_HTML);
        CODE_MAP.put("text/json", SyntaxConstants.SYNTAX_STYLE_JSON_WITH_COMMENTS);
        CODE_MAP.put("application/json", SyntaxConstants.SYNTAX_STYLE_JSON);
        CODE_MAP.put("text/xml", SyntaxConstants.SYNTAX_STYLE_XML);
        CODE_MAP.put("application/xml", SyntaxConstants.SYNTAX_STYLE_XML);
    }

    public static String getSyntaxEditingStyle(String mimeType) {
        if (mimeType != null) {
            return CODE_MAP.getOrDefault(mimeType.toLowerCase(), SyntaxConstants.SYNTAX_STYLE_HTML);
        }
        else {
            return SyntaxConstants.SYNTAX_STYLE_HTML;
        }
    }

    private byte[] content = null;

    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        try {
            if (content == null) {
                this.clearView();
//                this.txtURaw.setContentType("text/html");
                this.txtURaw.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_HTML);
            } else {
                this.content = content;
                BurpExtender extenderImpl = BurpExtender.getInstance();
                String guessCharset = null;
                HttpMessage httpMessage = null;
                if (isRequest) {
                    HttpRequest httpRequest = HttpRequest.parseHttpRequest(content);
                    httpMessage = httpRequest;
                    guessCharset = httpRequest.getGuessCharset();
                } else {
                    HttpResponse httpResponse = HttpResponse.parseHttpResponse(content);
                    httpMessage = httpResponse;
                    guessCharset = httpResponse.getGuessCharset();
                    String contentType = httpResponse.getContentMimeType();
  //                  this.txtURaw.setContentType(contentType == null ? "text/html" : contentType);
                    this.txtURaw.setSyntaxEditingStyle(getSyntaxEditingStyle(contentType));
                }
                if (guessCharset == null) {
                    guessCharset = StandardCharsets.ISO_8859_1.name();
                }
                this.quickSearchTab.getEncodingComboBox().removeItemListener(this.encodingItemStateChanged);
                this.quickSearchTab.renewEncodingList(guessCharset, extenderImpl.getSelectEncodingList());

                this.encodingItemStateChanged.itemStateChanged(null);
                this.quickSearchTab.getEncodingComboBox().addItemListener(this.encodingItemStateChanged);

                this.textModified = false;
            }
        } catch (ParseException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    @Override
    public byte[] getMessage() {
        if (this.content != null) {
            if (this.textModified) {
                String modifiedText = this.txtURaw.getText();
                String encoding = quickSearchTab.getSelectedEncoding();
                if (encoding != null) {
                    try {
                        return StringUtil.getBytesCharset(modifiedText, encoding);
                    } catch (UnsupportedEncodingException ex) {
                        return null;
                    }
                } else {
                    return this.content;
                }
            } else {
                return this.content;
            }
        } else {
            return new byte[]{};
        }
    }

    @Override
    public boolean isModified() {
        return this.textModified;
    }

    @Override
    public byte[] getSelectedData() {
        return null;
    }

    public String getSelectedText() {
        return this.txtURaw.getSelectedText();
    }

    public void clearView() {
        this.txtURaw.setText("");
        this.txtURaw.setEditable(false);
        this.quickSearchTab.clearView();
        this.content = null;
    }

    /**
     * @param lineWrap the lineWrap to set
     */
    public void setLineWrap(boolean lineWrap) {
        this.txtURaw.setLineWrap(lineWrap);
    }

}
