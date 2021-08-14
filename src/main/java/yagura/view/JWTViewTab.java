package yagura.view;

import burp.BurpExtender;
import burp.IExtensionStateListener;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;
import burp.IParameter;
import burp.IRequestInfo;
import extend.util.external.ThemeUI;
import extension.helpers.HttpMessage;
import extension.helpers.HttpRequest;
import extension.helpers.StringUtil;
import extension.helpers.SwingUtil;
import java.awt.Component;
import java.awt.Font;
import java.awt.SystemColor;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.UIManager;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import passive.JWTToken;
import yagura.model.UniversalViewProperty;

/**
 *
 * @author isayan
 */
public class JWTViewTab extends javax.swing.JPanel implements IMessageEditorTabFactory, IMessageEditorTab, IExtensionStateListener {

    private final static Logger logger = Logger.getLogger(JWTViewTab.class.getName());

    private JWTToken jwtinstance = new JWTToken();

    private IMessageEditorController controller = null;

    /**
     * Creates new form JWTView
     */
    public JWTViewTab() {
        this(null, false);
    }

    /**
     * Creates new form JWTView
     */
    public JWTViewTab(IMessageEditorController controller, boolean editable) {
        this.controller = controller;
        initComponents();
        customizeComponents();
    }

    final PropertyChangeListener listener = new PropertyChangeListener() {
        @Override
        public void propertyChange(PropertyChangeEvent evt) {
            ThemeUI.changeStyleTheme(txtHeaderJSON);
            ThemeUI.changeStyleTheme(txtPayloadJSON);
            ThemeUI.changeStyleTheme(txtSignatureSign);
        }
    };

//    private final JSONView jsonHeaderView = new JSONView();
//    private final JSONView jsonPayloadView = new JSONView();
    private org.fife.ui.rtextarea.RTextScrollPane scrollHeaderJSON;
    private org.fife.ui.rsyntaxtextarea.RSyntaxTextArea txtHeaderJSON;

    private org.fife.ui.rtextarea.RTextScrollPane scrollPayloadJSON;
    private org.fife.ui.rsyntaxtextarea.RSyntaxTextArea txtPayloadJSON;

    private org.fife.ui.rtextarea.RTextScrollPane scrollSignatureSign;
    private org.fife.ui.rsyntaxtextarea.RSyntaxTextArea txtSignatureSign;

    @SuppressWarnings("unchecked")
    private void customizeComponents() {

        /**
         * * UI design start **
         */

        /* Header */
        this.txtHeaderJSON = new org.fife.ui.rsyntaxtextarea.RSyntaxTextArea();
        this.scrollHeaderJSON = new org.fife.ui.rtextarea.RTextScrollPane(this.txtHeaderJSON);
        this.txtHeaderJSON.setWrapStyleWord(false);

        this.txtHeaderJSON.setCodeFoldingEnabled(true);
        this.txtHeaderJSON.setClearWhitespaceLinesEnabled(true);
        this.txtHeaderJSON.setHighlightCurrentLine(false);
        this.txtHeaderJSON.setCurrentLineHighlightColor(SystemColor.textHighlight);
        this.txtHeaderJSON.setBackground(SystemColor.text);
        this.txtHeaderJSON.setEditable(false);
        this.txtHeaderJSON.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JSON);

//        scrollURaw.setViewportView(txtURaw);
        this.scrollHeaderJSON.setLineNumbersEnabled(false);
        this.pnlHeader.add(this.scrollHeaderJSON, java.awt.BorderLayout.CENTER);

        /* Payload */
        this.txtPayloadJSON = new org.fife.ui.rsyntaxtextarea.RSyntaxTextArea();
        this.scrollPayloadJSON = new org.fife.ui.rtextarea.RTextScrollPane(this.txtPayloadJSON);
        this.txtPayloadJSON.setWrapStyleWord(false);

        this.txtPayloadJSON.setCodeFoldingEnabled(true);
        this.txtPayloadJSON.setClearWhitespaceLinesEnabled(true);
        this.txtPayloadJSON.setHighlightCurrentLine(false);
        this.txtPayloadJSON.setCurrentLineHighlightColor(SystemColor.textHighlight);
        this.txtPayloadJSON.setBackground(SystemColor.text);
        this.txtPayloadJSON.setEditable(false);
        this.txtPayloadJSON.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JSON);
//        scrollURaw.setViewportView(txtURaw);

        this.pnlPayload.add(this.scrollPayloadJSON, java.awt.BorderLayout.CENTER);

        /* Signature */
        this.txtSignatureSign = new org.fife.ui.rsyntaxtextarea.RSyntaxTextArea();
        this.scrollSignatureSign = new org.fife.ui.rtextarea.RTextScrollPane(this.txtSignatureSign);
        this.txtSignatureSign.setWrapStyleWord(false);

        this.txtSignatureSign.setCodeFoldingEnabled(true);
        this.txtSignatureSign.setClearWhitespaceLinesEnabled(true);
        this.txtSignatureSign.setHighlightCurrentLine(false);
        this.txtSignatureSign.setCurrentLineHighlightColor(SystemColor.textHighlight);
        this.txtSignatureSign.setBackground(SystemColor.text);
        this.txtSignatureSign.setEditable(false);
//        scrollURaw.setViewportView(txtURaw);

        this.scrollSignatureSign.setLineNumbersEnabled(false);

        this.pnlSignature.add(this.scrollSignatureSign, java.awt.BorderLayout.CENTER);

        /**
         * * UI design end **
         */
//        this.txtHeaderJSON.setEditable(false);
//        this.txtHeaderJSON.setEditorKitForContentType("text/json", this.jsonStyleEditorKit);
//        this.txtHeaderJSON.setContentType("text/json");
//        this.txtPayloadJSON.setEditable(false);
//        this.txtPayloadJSON.setEditorKitForContentType("text/json", this.jsonStyleEditorKit);
//        this.txtPayloadJSON.setContentType("text/json");

        this.listener.propertyChange(null);
        UIManager.addPropertyChangeListener(listener);

    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        pnlParam = new javax.swing.JPanel();
        cmbParam = new javax.swing.JComboBox<>();
        btnCopy = new javax.swing.JButton();
        pnlJWT = new javax.swing.JPanel();
        pnlHeader = new javax.swing.JPanel();
        lblHeader = new javax.swing.JLabel();
        pnlPayload = new javax.swing.JPanel();
        lblPayload = new javax.swing.JLabel();
        pnlSignature = new javax.swing.JPanel();
        lblSignature = new javax.swing.JLabel();

        setLayout(new java.awt.BorderLayout());

        pnlParam.setLayout(new java.awt.BorderLayout());

        cmbParam.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                cmbParamItemStateChanged(evt);
            }
        });
        pnlParam.add(cmbParam, java.awt.BorderLayout.CENTER);

        btnCopy.setText("Copy");
        btnCopy.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnCopyActionPerformed(evt);
            }
        });
        pnlParam.add(btnCopy, java.awt.BorderLayout.EAST);

        add(pnlParam, java.awt.BorderLayout.NORTH);

        pnlJWT.setLayout(new java.awt.BorderLayout());

        pnlHeader.setLayout(new java.awt.BorderLayout());

        lblHeader.setText("Header");
        pnlHeader.add(lblHeader, java.awt.BorderLayout.PAGE_START);

        pnlJWT.add(pnlHeader, java.awt.BorderLayout.NORTH);

        pnlPayload.setLayout(new java.awt.BorderLayout());

        lblPayload.setText("Payload");
        pnlPayload.add(lblPayload, java.awt.BorderLayout.PAGE_START);

        pnlJWT.add(pnlPayload, java.awt.BorderLayout.CENTER);

        pnlSignature.setPreferredSize(new java.awt.Dimension(108, 60));
        pnlSignature.setLayout(new java.awt.BorderLayout());

        lblSignature.setText("Signature");
        pnlSignature.add(lblSignature, java.awt.BorderLayout.PAGE_START);

        pnlJWT.add(pnlSignature, java.awt.BorderLayout.SOUTH);

        add(pnlJWT, java.awt.BorderLayout.CENTER);
    }// </editor-fold>//GEN-END:initComponents

    private void cmbParamItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_cmbParamItemStateChanged
        String key = (String) this.cmbParam.getSelectedItem();
        JWTToken token = this.tokenMap.get(key);
        if (token != null) {
//            this.jsonHeaderView.setMessage(jwt.getHeaderJSON(true));
//            this.jsonPayloadView.setMessage(jwt.getPayloadJSON(true));
            this.txtHeaderJSON.setText(token.getHeaderJSON(true));
            this.txtPayloadJSON.setText(token.getPayloadJSON(true));
            this.txtSignatureSign.setText(token.getSignature());
        }
    }//GEN-LAST:event_cmbParamItemStateChanged

    private void btnCopyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnCopyActionPerformed
        String key = (String) this.cmbParam.getSelectedItem();
        if (key != null) {
            SwingUtil.systemClipboardCopy(key);
        }
    }//GEN-LAST:event_btnCopyActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btnCopy;
    private javax.swing.JComboBox<String> cmbParam;
    private javax.swing.JLabel lblHeader;
    private javax.swing.JLabel lblPayload;
    private javax.swing.JLabel lblSignature;
    private javax.swing.JPanel pnlHeader;
    private javax.swing.JPanel pnlJWT;
    private javax.swing.JPanel pnlParam;
    private javax.swing.JPanel pnlPayload;
    private javax.swing.JPanel pnlSignature;
    // End of variables declaration//GEN-END:variables

    public void setMessageFont(Font font) {
//        this.jsonHeaderView.setMessageFont(font);
//        this.jsonPayloadView.setMessageFont(font);
        this.txtPayloadJSON.setFont(font);
        this.txtPayloadJSON.setFont(font);
        this.txtSignatureSign.setFont(font);
    }

    public boolean isExtendVisible() {
        return false;
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        this.txtPayloadJSON.setEditable(false);
        this.txtPayloadJSON.setEditable(false);
        this.txtSignatureSign.setEditable(false);
        return this;
    }

    @Override
    public String getTabCaption() {
        return "JWT";
    }

    @Override
    public Component getUiComponent() {
        return this;
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isMessageRequest) {
        if (!isMessageRequest) {
            return false;
        }
        if (content == null || content.length == 0) {
            return false;
        }
        boolean find = false;
        try {
            UniversalViewProperty viewProperty = BurpExtender.getInstance().getProperty().getEncodingProperty();
            EnumSet<UniversalViewProperty.UniversalView> view = viewProperty.getMessageView();
            if (!view.contains(UniversalViewProperty.UniversalView.JWT)) {
                return false;
            }
            if (content.length > viewProperty.getDispayMaxLength() && viewProperty.getDispayMaxLength() != 0) {
                return false;
            }
            this.setLineWrap(viewProperty.isLineWrap());
            IRequestInfo reqInfo = BurpExtender.getHelpers().analyzeRequest(content);
            List<String> headers = reqInfo.getHeaders();
            for (String h : headers) {
                if (JWTToken.containsTokenFormat(h)) {
                    return true;
                }
            }
            List<IParameter> parameters = reqInfo.getParameters();
            for (IParameter p : parameters) {
                if (p.getType() == IParameter.PARAM_URL || p.getType() == IParameter.PARAM_BODY) {
                    find = jwtinstance.isValidFormat(p.getValue());
                    if (find) {
                        break;
                    }
                }
            }
            if (!find) {
                String body = StringUtil.getStringRaw(Arrays.copyOfRange(content, reqInfo.getBodyOffset(), content.length));
                find = JWTToken.containsTokenFormat(body);
            }
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return find;
    }

    private final static Pattern HEADER = Pattern.compile("^(\\w+):\\s*(.*)");
    private final static Pattern COOKIE = Pattern.compile("([^\\s=]+)=([^\\s;]+);?");

    private final Map<String, JWTToken> tokenMap = Collections.synchronizedMap(new HashMap<>());

    private final static String[] TYPES = {"(URL)", "(Body)", "(Cookie)", "(XML)", "-", "(file)", "(JSON)"};

    public void setJWT(byte[] message) {
        this.tokenMap.clear();
        this.cmbParam.removeAllItems();
        IRequestInfo reqInfo = BurpExtender.getHelpers().analyzeRequest(message);
        List<String> headers = reqInfo.getHeaders();
        for (String h : headers) {
            Matcher m = HEADER.matcher(h);
            if (m.matches()) {
                String value = m.group(2);
                JWTToken token = jwtinstance.parseToken(value, false);
                if (token != null) {
                    tokenMap.put(h, token);
                    this.cmbParam.addItem(h);
                }
            }
        }
        boolean find = false;
        List<IParameter> parameters = reqInfo.getParameters();
        for (IParameter p : parameters) {
            if (JWTToken.containsTokenFormat(p.getValue())) {
                if (p.getType() == IParameter.PARAM_COOKIE) {
                    String name = p.getName();
                    String value = p.getValue();
                    String key = TYPES[p.getType()] + " " + name;
                    JWTToken token = jwtinstance.parseToken(value, true);
                    if (token != null) {
                        tokenMap.put(key, token);
                        this.cmbParam.addItem(key);
                    }
                } else if (p.getType() == IParameter.PARAM_URL || p.getType() == IParameter.PARAM_BODY) {
                    String name = p.getName();
                    String value = p.getValue();
                    String key = TYPES[p.getType()] + " " + name;
                    JWTToken token = jwtinstance.parseToken(value, true);
                    if (token != null) {
                        tokenMap.put(key, token);
                        this.cmbParam.addItem(key);
                        find = true;
                    }
                }
            }
        }
        if (!find) {
            String body = StringUtil.getBytesRawString(Arrays.copyOfRange(message, reqInfo.getBodyOffset(), message.length));
            if (JWTToken.containsTokenFormat(body)) {
                JWTToken token = jwtinstance.parseToken(body, false);
                if (token != null) {
                    String key = "(body)";
                    tokenMap.put(key, token);
                    this.cmbParam.addItem(key);
                }
            }
        }
    }

    private HttpMessage message = null;

    @Override
    public void setMessage(byte[] content, boolean isMessageRequest) {
        try {
            HttpMessage httpmessage = null;
            if (isMessageRequest) {
                HttpRequest request = HttpRequest.parseHttpRequest(content);
                httpmessage = request;
                this.setJWT(content);
            }
            this.message = httpmessage;
        } catch (ParseException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    @Override
    public byte[] getMessage() {
        if (this.message != null) {
            return this.message.getMessageBytes();
        } else {
            return new byte[]{};
        }
    }

    @Override
    public boolean isModified() {
        return false;
    }

    @Override
    public byte[] getSelectedData() {
        return null;
    }

    /**
     * @param lineWrap the lineWrap to set
     */
    private void setLineWrap(boolean lineWrap) {
        this.txtHeaderJSON.setLineWrap(lineWrap);
        this.txtPayloadJSON.setLineWrap(lineWrap);
        this.txtSignatureSign.setLineWrap(lineWrap);
    }

    @Override
    public void extensionUnloaded() {
        UIManager.removePropertyChangeListener(listener);
    }

}
