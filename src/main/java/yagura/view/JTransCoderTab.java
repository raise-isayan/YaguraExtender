package yagura.view;

import burp.ITab;
import extend.model.base.CustomTableModel;
import extend.util.ConvertUtil;
import extend.util.SwingUtil;
import extend.util.Util;
import extend.util.HashUtil;
import extend.view.model.VerticalFlowLayout;
import extend.util.CertUtil;
import extend.util.HttpUtil;
import extend.util.external.TransUtil;
import java.awt.BorderLayout;
import java.awt.Component;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.IllegalFormatException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.util.Map;
import javax.swing.MutableComboBoxModel;
import java.io.BufferedOutputStream;
import java.math.BigInteger;
import java.util.HashSet;
import java.util.concurrent.ExecutionException;
import javax.swing.SwingWorker;
import org.jdatepicker.JDateComponentFactory;
import org.jdatepicker.impl.JDatePickerImpl;
import extend.util.external.FormatUtil;
import extend.util.external.TransUtil.ConvertCase;
import extend.util.external.TransUtil.DateUnit;
import extend.util.external.TransUtil.EncodeType;
import extend.util.external.TransUtil.NewLine;
import java.awt.SystemColor;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import yagura.model.JTransCoderProperty;
import yagura.model.UniversalViewProperty;

/**
 *
 * @author isayan
 */
public class JTransCoderTab extends javax.swing.JPanel implements ITab {

    private final static Logger logger = Logger.getLogger(JTransCoderTab.class.getName());

    /**
     * Creates new form JTransCoder
     */
    public JTransCoderTab() {
        initComponents();
        customizeComponents();
    }
    private final QuickSearchTab quickSearchTabRaw = new QuickSearchTab();
    private final QuickSearchTab quickSearchTabFormat = new QuickSearchTab();

    private final SwingUtil.IntegerDocument BIN_DOC = new SwingUtil.IntegerDocument(2);
    private final SwingUtil.IntegerDocument OCT_DOC = new SwingUtil.IntegerDocument(8);
    private final SwingUtil.IntegerDocument DEC_DOC = new SwingUtil.IntegerDocument(10);
    private final SwingUtil.IntegerDocument HEX_DOC = new SwingUtil.IntegerDocument(16);
    private final SwingUtil.IntegerDocument RDX32_DOC = new SwingUtil.IntegerDocument(32);

    private org.fife.ui.rtextarea.RTextScrollPane scrollInputRaw;
    private org.fife.ui.rsyntaxtextarea.RSyntaxTextArea txtInputRaw;

    private org.fife.ui.rtextarea.RTextScrollPane scrollOutputRaw;
    private org.fife.ui.rsyntaxtextarea.RSyntaxTextArea txtOutputRaw;

    private org.fife.ui.rtextarea.RTextScrollPane scrollOutputFormat;
    private org.fife.ui.rsyntaxtextarea.RSyntaxTextArea txtOutputFormat;

    private void customizeComponents() {

        /**
         * * UI design start **
         */
//        this.txtInputRaw = new org.fife.ui.rsyntaxtextarea.RSyntaxTextArea();
        this.txtInputRaw = new org.fife.ui.rsyntaxtextarea.RSyntaxTextArea(20, 60);

        this.txtInputRaw.setEditable(true);
        this.txtInputRaw.setCodeFoldingEnabled(false);
        this.txtInputRaw.setHyperlinksEnabled(false);
        this.txtInputRaw.setHighlightCurrentLine(false);
        this.txtInputRaw.setHyperlinksEnabled(false);
        this.txtInputRaw.setBackground(SystemColor.text);

        this.scrollInputRaw = new org.fife.ui.rtextarea.RTextScrollPane(this.txtInputRaw);
//        this.tabbetInput.addTab("Raw", this.scrollInputRaw);
        this.pnlInputRaw.add(this.scrollInputRaw, BorderLayout.CENTER);
        
//        scrollURaw.setViewportView(txtURaw);
//        this.pnlInputRaw.add(this.scrollInputRaw, BorderLayout.CENTER);
        
        this.txtOutputRaw = new org.fife.ui.rsyntaxtextarea.RSyntaxTextArea();

        this.txtOutputRaw.setEditable(false);
        this.txtOutputRaw.setHyperlinksEnabled(false);
        this.txtOutputRaw.setHighlightCurrentLine(false);
        this.txtOutputRaw.setHyperlinksEnabled(false);
        this.txtOutputRaw.setBackground(SystemColor.text);

        this.scrollOutputRaw = new org.fife.ui.rtextarea.RTextScrollPane(this.txtOutputRaw);
        this.pnlOutputRaw.add(this.scrollOutputRaw, BorderLayout.CENTER);
        
        this.txtOutputFormat = new org.fife.ui.rsyntaxtextarea.RSyntaxTextArea();
        this.txtOutputFormat.setEditable(false);
        this.txtOutputFormat.setCodeFoldingEnabled(true);
        this.txtOutputFormat.setHyperlinksEnabled(false);
        this.txtOutputFormat.setHighlightCurrentLine(false);
        this.txtOutputFormat.setBackground(SystemColor.text);
        this.txtOutputFormat.setCurrentLineHighlightColor(SystemColor.textHighlight);

        this.scrollOutputFormat = new org.fife.ui.rtextarea.RTextScrollPane(this.txtOutputFormat);
        
        /**
         * * UI design end **
         */

        this.txtInputRaw.addCaretListener(new javax.swing.event.CaretListener() {
            public void caretUpdate(javax.swing.event.CaretEvent evt) {
                txtInputRawCaretUpdate(evt);
            }
        });

        this.txtOutputRaw.addCaretListener(new javax.swing.event.CaretListener() {
            public void caretUpdate(javax.swing.event.CaretEvent evt) {
                txtOutputRawCaretUpdate(evt);
            }
        });
        
        this.pnlTransButton.setLayout(new VerticalFlowLayout());

        this.tabbetOutput.addTab("Hex", this.hexOutputViewTab);
        this.hexOutputViewTab.setEnabled(false);

        this.tabbetInput.addTab("Hex", this.hexInputViewTab);
        this.hexInputViewTab.setEnabled(false);

        JDateComponentFactory componentFactory = new JDateComponentFactory();
        this.datePickerStart = (JDatePickerImpl) componentFactory.createJDatePicker();
        this.datePickerEnd = (JDatePickerImpl) componentFactory.createJDatePicker();
        this.datePickerEnd.getModel().addMonth(1);

        this.pnlDateStart.add(datePickerStart, BorderLayout.CENTER);
        this.pnlDateEnd.add(datePickerEnd, BorderLayout.CENTER);

        this.pnlDateStart.add(datePickerStart);
        this.pnlDateEnd.add(datePickerEnd);

        this.setEncodingList(UniversalViewProperty.getDefaultEncodingList(), "UTF-8");

        this.cmbEncoding.setEnabled(!this.chkRawMode.isSelected());

        this.pnlCharacter.setLayout(new VerticalFlowLayout());

        this.quickSearchTabRaw.setSelectedTextArea(this.txtOutputRaw);
        this.quickSearchTabRaw.getEncodingComboBox().setVisible(false);
        this.quickSearchTabFormat.setSelectedTextArea(this.txtOutputFormat);
        this.quickSearchTabFormat.getEncodingComboBox().setVisible(false);

//        this.scrollOutputFormat.setViewportView(this.txtOutputFormat);
        this.pnlOutputFormat.setLayout(new BorderLayout());
        this.pnlOutputFormat.add(this.scrollOutputFormat, BorderLayout.CENTER);
        this.pnlOutputRaw.add(this.quickSearchTabRaw, java.awt.BorderLayout.SOUTH);
        this.pnlOutputFormat.add(this.quickSearchTabFormat, java.awt.BorderLayout.SOUTH);

        this.cmbHistory.addActionListener(this.historyActionPerformed);
//        this.cmbHistory.addItemListener(this.historyItemStateChanged);

        // Base conversion
        this.txtBin.setDocument(BIN_DOC);
        this.txtBin.setText("0");
        this.txtOct.setDocument(OCT_DOC);
        this.txtOct.setText("0");
        this.txtDec.setDocument(DEC_DOC);
        this.txtDec.setText("0");
        this.txtHex.setDocument(HEX_DOC);
        this.txtHex.setText("0");
        this.txtRadix32.setDocument(RDX32_DOC);
        this.txtRadix32.setText("0");
//        // Drag and Drop
//        this.txtInputRaw.setTransferHandler(new SwingUtil.FileDropAndClipbordTransferHandler() {
//
//            @Override
//            public void setData(byte[] rawData) {
//                setInputText(Util.getRawStr(rawData));
//            }
//
//        });
        this.doStateDecodeChange();

    }

    private void txtInputRawCaretUpdate(javax.swing.event.CaretEvent evt) {
        this.caretUpdate(this.txtInputRaw);
    }

    private void txtOutputRawCaretUpdate(javax.swing.event.CaretEvent evt) {
        this.caretUpdate(this.txtOutputRaw);
    }

    /**
     * This method is called from within the constructor to initialize the form. WARNING: Do NOT modify this code. The
     * content of this method is always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        btnGrpNewLine = new javax.swing.ButtonGroup();
        btnConvertCase = new javax.swing.ButtonGroup();
        btnGrpEncodeType = new javax.swing.ButtonGroup();
        rdoEncodeDecodeGrp = new javax.swing.ButtonGroup();
        rdoRandomLengthGrp = new javax.swing.ButtonGroup();
        rdoRandomCountGrp = new javax.swing.ButtonGroup();
        rdoCetificateGrp = new javax.swing.ButtonGroup();
        rdoFormatGrp = new javax.swing.ButtonGroup();
        tabbetTranscoder = new javax.swing.JTabbedPane();
        tabTransrator = new javax.swing.JPanel();
        pnlTransButton = new javax.swing.JPanel();
        pnlEncodeDecode = new javax.swing.JPanel();
        btnSmartDecode = new javax.swing.JButton();
        pnlEncDec = new javax.swing.JPanel();
        btnEncode = new javax.swing.JButton();
        btnDecode = new javax.swing.JButton();
        pnlUrl = new javax.swing.JPanel();
        rdoUrl = new javax.swing.JRadioButton();
        rdoUrlUnicode = new javax.swing.JRadioButton();
        pnlBase64 = new javax.swing.JPanel();
        rdoBase64 = new javax.swing.JRadioButton();
        chk64Newline = new javax.swing.JCheckBox();
        chk76Newline = new javax.swing.JCheckBox();
        chkPadding = new javax.swing.JCheckBox();
        pnlBase64URLSafe = new javax.swing.JPanel();
        rdoBase64URLSafe = new javax.swing.JRadioButton();
        pnlBaseN = new javax.swing.JPanel();
        rdoBase32 = new javax.swing.JRadioButton();
        rdoBase16 = new javax.swing.JRadioButton();
        chkNPadding = new javax.swing.JCheckBox();
        pnlMail = new javax.swing.JPanel();
        rdoQuotedPrintable = new javax.swing.JRadioButton();
        rdoPunycode = new javax.swing.JRadioButton();
        pnlHtmlEnc = new javax.swing.JPanel();
        rdoHtml = new javax.swing.JRadioButton();
        rdoHtmlDec = new javax.swing.JRadioButton();
        pnlHtmlHex = new javax.swing.JPanel();
        rdoHtmlHex = new javax.swing.JRadioButton();
        rdoHtmlByteHex = new javax.swing.JRadioButton();
        pnlJSHexEnc = new javax.swing.JPanel();
        rdoUnicodeHex = new javax.swing.JRadioButton();
        rdoByteHex = new javax.swing.JRadioButton();
        rdoByteHex2 = new javax.swing.JRadioButton();
        rdoByteOct = new javax.swing.JRadioButton();
        pnlCompress = new javax.swing.JPanel();
        rdoGzip = new javax.swing.JRadioButton();
        rdoZLIB = new javax.swing.JRadioButton();
        pnlILLUTF8 = new javax.swing.JPanel();
        rdoUTF7 = new javax.swing.JRadioButton();
        rdoILLUTF8 = new javax.swing.JRadioButton();
        cmbIILUTF8 = new javax.swing.JComboBox();
        pnlLang = new javax.swing.JPanel();
        rdoCLang = new javax.swing.JRadioButton();
        rdoSQLLang = new javax.swing.JRadioButton();
        rdoRegex = new javax.swing.JRadioButton();
        pnlFormat = new javax.swing.JPanel();
        rdoMinifyFormat = new javax.swing.JRadioButton();
        rdoBeautifyFormat = new javax.swing.JRadioButton();
        btnSmartFormat = new javax.swing.JButton();
        pnlRegex = new javax.swing.JPanel();
        btnSmartMatch = new javax.swing.JButton();
        chkWithByte = new javax.swing.JCheckBox();
        pnlHashTrans = new javax.swing.JPanel();
        btnHashMd2 = new javax.swing.JButton();
        btnHashMd5 = new javax.swing.JButton();
        btnHashSha1 = new javax.swing.JButton();
        btnHashSha256 = new javax.swing.JButton();
        btnHashSha384 = new javax.swing.JButton();
        btnHashSha512 = new javax.swing.JButton();
        btnCRC32 = new javax.swing.JButton();
        btnAdler32 = new javax.swing.JButton();
        btnMurmurHash32 = new javax.swing.JButton();
        btnMurmurHash64 = new javax.swing.JButton();
        pnlTranslator = new javax.swing.JPanel();
        pnlConvert = new javax.swing.JPanel();
        pnlHeader = new javax.swing.JPanel();
        lblPositionStatus = new javax.swing.JLabel();
        cmbHistory = new javax.swing.JComboBox<>();
        splitConvert = new javax.swing.JSplitPane();
        tabbetInput = new javax.swing.JTabbedPane();
        pnlInputRaw = new javax.swing.JPanel();
        tabbetOutput = new javax.swing.JTabbedPane();
        pnlOutputRaw = new javax.swing.JPanel();
        pnlStatus = new javax.swing.JPanel();
        pnlInput = new javax.swing.JPanel();
        btnInputfile = new javax.swing.JButton();
        scrollStatus = new javax.swing.JScrollPane();
        txtStatus = new javax.swing.JTextArea();
        btnOutput = new javax.swing.JPanel();
        btnOutputfile = new javax.swing.JButton();
        pnlSelect = new javax.swing.JPanel();
        pnlInputOutput = new javax.swing.JPanel();
        pnlEncoding = new javax.swing.JPanel();
        cmbEncoding = new javax.swing.JComboBox<>();
        chkRawMode = new javax.swing.JCheckBox();
        chkGuess = new javax.swing.JCheckBox();
        pnlOutputToInput = new javax.swing.JPanel();
        btnOutputToInput = new javax.swing.JButton();
        btnClear = new javax.swing.JButton();
        btnOutputCopy = new javax.swing.JButton();
        pnlSelectOption = new javax.swing.JPanel();
        pnlEncode = new javax.swing.JPanel();
        rdoAll = new javax.swing.JRadioButton();
        rdoAlphaNum = new javax.swing.JRadioButton();
        rdoLigth = new javax.swing.JRadioButton();
        rdoStandard = new javax.swing.JRadioButton();
        pnlConvertCase = new javax.swing.JPanel();
        rdoLowerCase = new javax.swing.JRadioButton();
        rdoUpperCase = new javax.swing.JRadioButton();
        pnlNewLine = new javax.swing.JPanel();
        rdoNone = new javax.swing.JRadioButton();
        rdoCR = new javax.swing.JRadioButton();
        rdoLF = new javax.swing.JRadioButton();
        rdoCRLF = new javax.swing.JRadioButton();
        pnlWrap = new javax.swing.JPanel();
        chkViewLineWrap = new javax.swing.JCheckBox();
        tabGenerator = new javax.swing.JPanel();
        splitGenerator = new javax.swing.JSplitPane();
        scrollGenerate = new javax.swing.JScrollPane();
        txtGenarate = new javax.swing.JTextArea();
        pnlTop = new javax.swing.JPanel();
        tabbetGenerate = new javax.swing.JTabbedPane();
        tabSequence = new javax.swing.JPanel();
        pnlGenerate = new javax.swing.JPanel();
        tabbetSequence = new javax.swing.JTabbedPane();
        pnlNumbers = new javax.swing.JPanel();
        txtNumFormat = new javax.swing.JTextField();
        lblNumFormat = new javax.swing.JLabel();
        lblNumStart = new javax.swing.JLabel();
        lblNumEnd = new javax.swing.JLabel();
        lblNumStep = new javax.swing.JLabel();
        spnNumStep = new javax.swing.JSpinner();
        spnNumStart = new javax.swing.JSpinner();
        spnNumEnd = new javax.swing.JSpinner();
        pnlDate = new javax.swing.JPanel();
        txtDateFormat = new javax.swing.JTextField();
        lblDateFormat = new javax.swing.JLabel();
        lblDateStart = new javax.swing.JLabel();
        lblDateEnd = new javax.swing.JLabel();
        lblDateStep = new javax.swing.JLabel();
        pnlDateEnd = new javax.swing.JPanel();
        pnlDateStart = new javax.swing.JPanel();
        cmbDateUnit = new javax.swing.JComboBox<>();
        spnDateStep = new javax.swing.JSpinner();
        tabRandom = new javax.swing.JPanel();
        pnlCharacter = new javax.swing.JPanel();
        chkCharacterNumber = new javax.swing.JCheckBox();
        chkCharacterLowerCase = new javax.swing.JCheckBox();
        chkCharacterUpperCase = new javax.swing.JCheckBox();
        chkCharacterSpace = new javax.swing.JCheckBox();
        chkCharacterUnderline = new javax.swing.JCheckBox();
        pnlCustom = new javax.swing.JPanel();
        chkCharacterCustom = new javax.swing.JCheckBox();
        txtCustom = new javax.swing.JTextField();
        pnlStringLength = new javax.swing.JPanel();
        rdoLength4 = new javax.swing.JRadioButton();
        rdoLength8 = new javax.swing.JRadioButton();
        rdoLength16 = new javax.swing.JRadioButton();
        rdoLengthNum = new javax.swing.JRadioButton();
        spnLengthNum = new javax.swing.JSpinner();
        pnlCount = new javax.swing.JPanel();
        rdoCount1 = new javax.swing.JRadioButton();
        rdoCount10 = new javax.swing.JRadioButton();
        rdoCount50 = new javax.swing.JRadioButton();
        rdoCountNum = new javax.swing.JRadioButton();
        spnCountNum = new javax.swing.JSpinner();
        pnlRight = new javax.swing.JPanel();
        btnGenerate = new javax.swing.JButton();
        txtListCopy = new javax.swing.JButton();
        btnSavetoFile = new javax.swing.JButton();
        tabBaseBaseConverter = new javax.swing.JPanel();
        lblBin = new javax.swing.JLabel();
        lblOct = new javax.swing.JLabel();
        lblDec = new javax.swing.JLabel();
        lblHex = new javax.swing.JLabel();
        lblRadix32 = new javax.swing.JLabel();
        txtBin = new javax.swing.JTextField();
        txtOct = new javax.swing.JTextField();
        txtDec = new javax.swing.JTextField();
        txtHex = new javax.swing.JTextField();
        txtRadix32 = new javax.swing.JTextField();
        btnBinCopy = new javax.swing.JButton();
        btnOctCopy = new javax.swing.JButton();
        btnDecCopy = new javax.swing.JButton();
        btnHexCopy = new javax.swing.JButton();
        btnRadix32Copy = new javax.swing.JButton();
        pnlCertificate = new javax.swing.JPanel();
        btnExport = new javax.swing.JButton();
        rdoConvertPEM = new javax.swing.JRadioButton();
        txtStoreFile = new javax.swing.JTextField();
        btnImport = new javax.swing.JButton();
        lblPassword = new javax.swing.JLabel();
        txtStorePassword = new javax.swing.JTextField();
        btnStoreTypeJKS = new javax.swing.JToggleButton();
        btnStoreTypePKCS12 = new javax.swing.JToggleButton();
        tabTokenStrength = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        txtTokenList = new javax.swing.JTextArea();
        txtBase = new javax.swing.JTextField();
        txtExponent = new javax.swing.JTextField();
        txtStrength = new javax.swing.JTextField();
        btnCalc = new javax.swing.JButton();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        btnAnalyze = new javax.swing.JButton();
        lblmaximum = new javax.swing.JLabel();

        setLayout(new java.awt.BorderLayout());

        tabTransrator.setLayout(new java.awt.BorderLayout());

        pnlTransButton.setLayout(new javax.swing.BoxLayout(pnlTransButton, javax.swing.BoxLayout.PAGE_AXIS));

        pnlEncodeDecode.setBorder(javax.swing.BorderFactory.createTitledBorder("Encode/Decode"));
        pnlEncodeDecode.setLayout(new java.awt.GridLayout(14, 0));

        btnSmartDecode.setText("Smart Decode");
        btnSmartDecode.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnSmartDecodeActionPerformed(evt);
            }
        });
        pnlEncodeDecode.add(btnSmartDecode);

        pnlEncDec.setLayout(new java.awt.GridLayout(1, 1));

        btnEncode.setText("Encode");
        btnEncode.setMaximumSize(new java.awt.Dimension(71, 21));
        btnEncode.setMinimumSize(new java.awt.Dimension(71, 21));
        btnEncode.setPreferredSize(new java.awt.Dimension(71, 21));
        btnEncode.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnEncodeActionPerformed(evt);
            }
        });
        pnlEncDec.add(btnEncode);

        btnDecode.setText("Decode");
        btnDecode.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnDecodeActionPerformed(evt);
            }
        });
        pnlEncDec.add(btnDecode);

        pnlEncodeDecode.add(pnlEncDec);

        pnlUrl.setLayout(new java.awt.GridLayout(1, 2));

        rdoEncodeDecodeGrp.add(rdoUrl);
        rdoUrl.setSelected(true);
        rdoUrl.setText("URL(%hh)");
        pnlUrl.add(rdoUrl);

        rdoEncodeDecodeGrp.add(rdoUrlUnicode);
        rdoUrlUnicode.setText("URL(%uhhhh)");
        pnlUrl.add(rdoUrlUnicode);

        pnlEncodeDecode.add(pnlUrl);

        pnlBase64.setLayout(new java.awt.GridLayout(1, 4));

        rdoEncodeDecodeGrp.add(rdoBase64);
        rdoBase64.setText("Base64");
        pnlBase64.add(rdoBase64);

        chk64Newline.setText("64 newline");
        chk64Newline.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                chk64NewlineActionPerformed(evt);
            }
        });
        pnlBase64.add(chk64Newline);

        chk76Newline.setText("76 newline");
        chk76Newline.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                chk76NewlineActionPerformed(evt);
            }
        });
        pnlBase64.add(chk76Newline);

        chkPadding.setSelected(true);
        chkPadding.setText("Padding");
        pnlBase64.add(chkPadding);

        pnlEncodeDecode.add(pnlBase64);

        pnlBase64URLSafe.setLayout(new java.awt.GridLayout(1, 0));

        rdoEncodeDecodeGrp.add(rdoBase64URLSafe);
        rdoBase64URLSafe.setText("Base64URLSafe");
        pnlBase64URLSafe.add(rdoBase64URLSafe);

        pnlEncodeDecode.add(pnlBase64URLSafe);

        pnlBaseN.setLayout(new java.awt.GridLayout(1, 0));

        rdoEncodeDecodeGrp.add(rdoBase32);
        rdoBase32.setText("Base32");
        pnlBaseN.add(rdoBase32);

        rdoEncodeDecodeGrp.add(rdoBase16);
        rdoBase16.setText("Base16");
        rdoBase16.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                rdoBase16ActionPerformed(evt);
            }
        });
        pnlBaseN.add(rdoBase16);

        chkNPadding.setSelected(true);
        chkNPadding.setText("Padding");
        pnlBaseN.add(chkNPadding);

        pnlEncodeDecode.add(pnlBaseN);

        pnlMail.setLayout(new java.awt.GridLayout(1, 2));

        rdoEncodeDecodeGrp.add(rdoQuotedPrintable);
        rdoQuotedPrintable.setText("QuotedPrintable");
        rdoQuotedPrintable.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                rdoQuotedPrintableActionPerformed(evt);
            }
        });
        pnlMail.add(rdoQuotedPrintable);

        pnlEncodeDecode.add(pnlMail);

        rdoEncodeDecodeGrp.add(rdoPunycode);
        rdoPunycode.setText("puyencode");
        pnlEncodeDecode.add(rdoPunycode);

        pnlHtmlEnc.setLayout(new java.awt.GridLayout(1, 4));

        rdoEncodeDecodeGrp.add(rdoHtml);
        rdoHtml.setText("HTML(<,>,\",')");
        pnlHtmlEnc.add(rdoHtml);

        rdoEncodeDecodeGrp.add(rdoHtmlDec);
        rdoHtmlDec.setText("&#d;");
        pnlHtmlEnc.add(rdoHtmlDec);

        pnlEncodeDecode.add(pnlHtmlEnc);

        pnlHtmlHex.setLayout(new java.awt.GridLayout(1, 2));

        rdoEncodeDecodeGrp.add(rdoHtmlHex);
        rdoHtmlHex.setText("&#xhh;(unicode)");
        rdoHtmlHex.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                rdoHtmlHexActionPerformed(evt);
            }
        });
        pnlHtmlHex.add(rdoHtmlHex);

        rdoEncodeDecodeGrp.add(rdoHtmlByteHex);
        rdoHtmlByteHex.setText("&#xhh;(byte)");
        rdoHtmlByteHex.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                rdoHtmlByteHexActionPerformed(evt);
            }
        });
        pnlHtmlHex.add(rdoHtmlByteHex);

        pnlEncodeDecode.add(pnlHtmlHex);

        pnlJSHexEnc.setLayout(new java.awt.GridLayout(1, 1));

        rdoEncodeDecodeGrp.add(rdoUnicodeHex);
        rdoUnicodeHex.setText("\\uhhhh");
        pnlJSHexEnc.add(rdoUnicodeHex);

        rdoEncodeDecodeGrp.add(rdoByteHex);
        rdoByteHex.setText("\\xhh(hex)");
        rdoByteHex.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                rdoByteHexActionPerformed(evt);
            }
        });
        pnlJSHexEnc.add(rdoByteHex);

        rdoEncodeDecodeGrp.add(rdoByteHex2);
        rdoByteHex2.setText("\\h(hex)");
        rdoByteHex2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                rdoByteHex2ActionPerformed(evt);
            }
        });
        pnlJSHexEnc.add(rdoByteHex2);

        rdoEncodeDecodeGrp.add(rdoByteOct);
        rdoByteOct.setText("\\ooo(oct)");
        rdoByteOct.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                rdoByteOctActionPerformed(evt);
            }
        });
        pnlJSHexEnc.add(rdoByteOct);

        pnlEncodeDecode.add(pnlJSHexEnc);

        pnlCompress.setLayout(new java.awt.GridLayout(1, 2));

        rdoEncodeDecodeGrp.add(rdoGzip);
        rdoGzip.setText("Gzip");
        pnlCompress.add(rdoGzip);

        rdoEncodeDecodeGrp.add(rdoZLIB);
        rdoZLIB.setText("ZLIB");
        pnlCompress.add(rdoZLIB);

        pnlEncodeDecode.add(pnlCompress);

        pnlILLUTF8.setLayout(new java.awt.GridLayout(1, 3));

        rdoEncodeDecodeGrp.add(rdoUTF7);
        rdoUTF7.setText("UTF-7");
        pnlILLUTF8.add(rdoUTF7);

        rdoEncodeDecodeGrp.add(rdoILLUTF8);
        rdoILLUTF8.setText("UTF-8(URL)");
        rdoILLUTF8.setToolTipText("");
        rdoILLUTF8.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                rdoILLUTF8StateChanged(evt);
            }
        });
        pnlILLUTF8.add(rdoILLUTF8);

        cmbIILUTF8.setModel(new javax.swing.DefaultComboBoxModel(new String[] { "2", "3", "4" }));
        pnlILLUTF8.add(cmbIILUTF8);

        pnlEncodeDecode.add(pnlILLUTF8);

        pnlLang.setLayout(new java.awt.GridLayout(1, 3));

        rdoEncodeDecodeGrp.add(rdoCLang);
        rdoCLang.setText("C Lang");
        pnlLang.add(rdoCLang);

        rdoEncodeDecodeGrp.add(rdoSQLLang);
        rdoSQLLang.setText("SQL");
        pnlLang.add(rdoSQLLang);

        rdoEncodeDecodeGrp.add(rdoRegex);
        rdoRegex.setText("Regex");
        rdoRegex.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                rdoRegexStateChanged(evt);
            }
        });
        pnlLang.add(rdoRegex);

        pnlEncodeDecode.add(pnlLang);

        pnlTransButton.add(pnlEncodeDecode);

        pnlFormat.setBorder(javax.swing.BorderFactory.createTitledBorder("Format"));
        pnlFormat.setLayout(new java.awt.GridLayout(1, 2));

        rdoFormatGrp.add(rdoMinifyFormat);
        rdoMinifyFormat.setText("Minify");
        rdoMinifyFormat.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                rdoMinifyFormatActionPerformed(evt);
            }
        });
        pnlFormat.add(rdoMinifyFormat);

        rdoFormatGrp.add(rdoBeautifyFormat);
        rdoBeautifyFormat.setSelected(true);
        rdoBeautifyFormat.setText("Beautify");
        rdoBeautifyFormat.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                rdoBeautifyFormatActionPerformed(evt);
            }
        });
        pnlFormat.add(rdoBeautifyFormat);

        btnSmartFormat.setText("Smart Format");
        btnSmartFormat.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnSmartFormatActionPerformed(evt);
            }
        });
        pnlFormat.add(btnSmartFormat);

        pnlTransButton.add(pnlFormat);

        pnlRegex.setBorder(javax.swing.BorderFactory.createTitledBorder("Regex"));
        pnlRegex.setLayout(new java.awt.BorderLayout());

        btnSmartMatch.setText("Smart Match");
        btnSmartMatch.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnSmartMatchActionPerformed(evt);
            }
        });
        pnlRegex.add(btnSmartMatch, java.awt.BorderLayout.CENTER);

        chkWithByte.setText("with Byte");
        pnlRegex.add(chkWithByte, java.awt.BorderLayout.EAST);

        pnlTransButton.add(pnlRegex);

        pnlHashTrans.setBorder(javax.swing.BorderFactory.createTitledBorder("Hash/Checksum"));
        pnlHashTrans.setLayout(new java.awt.GridLayout(5, 2));

        btnHashMd2.setText("md2");
        btnHashMd2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashMd2ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashMd2);

        btnHashMd5.setText("md5");
        btnHashMd5.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashMd5ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashMd5);

        btnHashSha1.setText("sha1");
        btnHashSha1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashSha1ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashSha1);

        btnHashSha256.setText("sha256");
        btnHashSha256.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashSha256ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashSha256);

        btnHashSha384.setText("sha384");
        btnHashSha384.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashSha384ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashSha384);

        btnHashSha512.setText("sha512");
        btnHashSha512.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashSha512ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashSha512);

        btnCRC32.setText("CRC32");
        btnCRC32.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnCRC32ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnCRC32);

        btnAdler32.setText("Adler32");
        btnAdler32.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnAdler32ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnAdler32);

        btnMurmurHash32.setText("MurmurHash32");
        btnMurmurHash32.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnMurmurHash32ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnMurmurHash32);

        btnMurmurHash64.setText("MurmurHash64");
        btnMurmurHash64.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnMurmurHash64ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnMurmurHash64);

        pnlTransButton.add(pnlHashTrans);

        tabTransrator.add(pnlTransButton, java.awt.BorderLayout.EAST);

        pnlTranslator.setLayout(new java.awt.BorderLayout());

        pnlConvert.setLayout(new java.awt.BorderLayout());

        pnlHeader.setLayout(new java.awt.BorderLayout());

        lblPositionStatus.setText("Length:0 Position:0  SelectLength:0");
        pnlHeader.add(lblPositionStatus, java.awt.BorderLayout.WEST);

        pnlHeader.add(cmbHistory, java.awt.BorderLayout.CENTER);

        pnlConvert.add(pnlHeader, java.awt.BorderLayout.NORTH);

        splitConvert.setDividerLocation(200);
        splitConvert.setOrientation(javax.swing.JSplitPane.VERTICAL_SPLIT);
        splitConvert.setToolTipText("");

        tabbetInput.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                tabbetInputStateChanged(evt);
            }
        });

        pnlInputRaw.setLayout(new java.awt.BorderLayout());
        tabbetInput.addTab("Raw", pnlInputRaw);

        splitConvert.setTopComponent(tabbetInput);

        pnlOutputRaw.setLayout(new java.awt.BorderLayout());
        tabbetOutput.addTab("Raw", pnlOutputRaw);

        splitConvert.setBottomComponent(tabbetOutput);

        pnlConvert.add(splitConvert, java.awt.BorderLayout.CENTER);

        pnlStatus.setLayout(new java.awt.BorderLayout());

        btnInputfile.setText("Input from file");
        btnInputfile.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnInputfileActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout pnlInputLayout = new javax.swing.GroupLayout(pnlInput);
        pnlInput.setLayout(pnlInputLayout);
        pnlInputLayout.setHorizontalGroup(
            pnlInputLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlInputLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(btnInputfile, javax.swing.GroupLayout.PREFERRED_SIZE, 126, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        pnlInputLayout.setVerticalGroup(
            pnlInputLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlInputLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(btnInputfile)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        pnlStatus.add(pnlInput, java.awt.BorderLayout.NORTH);

        txtStatus.setEditable(false);
        txtStatus.setBackground(javax.swing.UIManager.getDefaults().getColor("Button.background"));
        txtStatus.setColumns(20);
        txtStatus.setFont(new java.awt.Font("Monospaced", 0, 12)); // NOI18N
        txtStatus.setRows(5);
        txtStatus.setTabSize(2);
        scrollStatus.setViewportView(txtStatus);

        pnlStatus.add(scrollStatus, java.awt.BorderLayout.CENTER);

        btnOutputfile.setText("Output to file");
        btnOutputfile.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnOutputfileActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout btnOutputLayout = new javax.swing.GroupLayout(btnOutput);
        btnOutput.setLayout(btnOutputLayout);
        btnOutputLayout.setHorizontalGroup(
            btnOutputLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(btnOutputLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(btnOutputfile, javax.swing.GroupLayout.PREFERRED_SIZE, 126, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        btnOutputLayout.setVerticalGroup(
            btnOutputLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(btnOutputLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(btnOutputfile)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        pnlStatus.add(btnOutput, java.awt.BorderLayout.SOUTH);

        pnlConvert.add(pnlStatus, java.awt.BorderLayout.WEST);

        pnlTranslator.add(pnlConvert, java.awt.BorderLayout.CENTER);

        pnlSelect.setLayout(new java.awt.BorderLayout());

        pnlInputOutput.setLayout(new java.awt.BorderLayout());

        pnlEncoding.setBorder(javax.swing.BorderFactory.createTitledBorder("Input Encoding"));

        cmbEncoding.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cmbEncodingActionPerformed(evt);
            }
        });

        chkRawMode.setText("Raw(8859_1)");
        chkRawMode.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                chkRawModeActionPerformed(evt);
            }
        });

        chkGuess.setText("Guess");
        chkGuess.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                chkGuessActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout pnlEncodingLayout = new javax.swing.GroupLayout(pnlEncoding);
        pnlEncoding.setLayout(pnlEncodingLayout);
        pnlEncodingLayout.setHorizontalGroup(
            pnlEncodingLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlEncodingLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(pnlEncodingLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(pnlEncodingLayout.createSequentialGroup()
                        .addComponent(cmbEncoding, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addContainerGap())
                    .addGroup(pnlEncodingLayout.createSequentialGroup()
                        .addComponent(chkRawMode)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(chkGuess)
                        .addGap(4, 32, Short.MAX_VALUE))))
        );
        pnlEncodingLayout.setVerticalGroup(
            pnlEncodingLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlEncodingLayout.createSequentialGroup()
                .addGroup(pnlEncodingLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(chkRawMode)
                    .addComponent(chkGuess))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(cmbEncoding, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );

        pnlInputOutput.add(pnlEncoding, java.awt.BorderLayout.CENTER);

        btnOutputToInput.setIcon(new javax.swing.ImageIcon(getClass().getResource("/yagura/resources/arrow_up.png"))); // NOI18N
        btnOutputToInput.setText("Output => Input");
        btnOutputToInput.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnOutputToInputActionPerformed(evt);
            }
        });

        btnClear.setText("Clear");
        btnClear.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnClearActionPerformed(evt);
            }
        });

        btnOutputCopy.setText("Output Copy");
        btnOutputCopy.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnOutputCopyActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout pnlOutputToInputLayout = new javax.swing.GroupLayout(pnlOutputToInput);
        pnlOutputToInput.setLayout(pnlOutputToInputLayout);
        pnlOutputToInputLayout.setHorizontalGroup(
            pnlOutputToInputLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, pnlOutputToInputLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(pnlOutputToInputLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.CENTER)
                    .addComponent(btnClear, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(btnOutputCopy, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(btnOutputToInput, javax.swing.GroupLayout.DEFAULT_SIZE, 182, Short.MAX_VALUE))
                .addContainerGap())
        );
        pnlOutputToInputLayout.setVerticalGroup(
            pnlOutputToInputLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlOutputToInputLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(btnClear)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(btnOutputCopy)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(btnOutputToInput)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        pnlInputOutput.add(pnlOutputToInput, java.awt.BorderLayout.PAGE_END);

        pnlSelect.add(pnlInputOutput, java.awt.BorderLayout.EAST);

        pnlEncode.setBorder(javax.swing.BorderFactory.createTitledBorder("Encode Type"));
        pnlEncode.setLayout(new java.awt.GridLayout(4, 0));

        btnGrpEncodeType.add(rdoAll);
        rdoAll.setSelected(true);
        rdoAll.setText("All");
        rdoAll.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                rdoAllActionPerformed(evt);
            }
        });
        pnlEncode.add(rdoAll);

        btnGrpEncodeType.add(rdoAlphaNum);
        rdoAlphaNum.setText("[^A-Za-z0-9]");
        rdoAlphaNum.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                rdoAlphaNumActionPerformed(evt);
            }
        });
        pnlEncode.add(rdoAlphaNum);

        btnGrpEncodeType.add(rdoLigth);
        rdoLigth.setText("[^A-Za-z0-9!\"$'()*,/:<>@\\[\\\\\\]^`{|}~]");
        rdoLigth.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                rdoLigthActionPerformed(evt);
            }
        });
        pnlEncode.add(rdoLigth);

        btnGrpEncodeType.add(rdoStandard);
        rdoStandard.setText("[^A-Za-z0-9\"<>\\[\\\\\\]^`{|}]");
        rdoStandard.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                rdoStandardActionPerformed(evt);
            }
        });
        pnlEncode.add(rdoStandard);

        pnlSelectOption.add(pnlEncode);

        pnlConvertCase.setBorder(javax.swing.BorderFactory.createTitledBorder("Convert Case"));
        pnlConvertCase.setLayout(new java.awt.GridLayout(4, 0));

        btnConvertCase.add(rdoLowerCase);
        rdoLowerCase.setSelected(true);
        rdoLowerCase.setText("LowerCase");
        rdoLowerCase.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                rdoLowerCaseActionPerformed(evt);
            }
        });
        pnlConvertCase.add(rdoLowerCase);

        btnConvertCase.add(rdoUpperCase);
        rdoUpperCase.setText("UpperCase");
        rdoUpperCase.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                rdoUpperCaseActionPerformed(evt);
            }
        });
        pnlConvertCase.add(rdoUpperCase);

        pnlSelectOption.add(pnlConvertCase);

        pnlNewLine.setBorder(javax.swing.BorderFactory.createTitledBorder("NewLine"));
        pnlNewLine.setLayout(new java.awt.GridLayout(4, 0));

        btnGrpNewLine.add(rdoNone);
        rdoNone.setSelected(true);
        rdoNone.setText("None");
        rdoNone.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                rdoNoneActionPerformed(evt);
            }
        });
        pnlNewLine.add(rdoNone);

        btnGrpNewLine.add(rdoCR);
        rdoCR.setText("CR");
        rdoCR.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                rdoCRActionPerformed(evt);
            }
        });
        pnlNewLine.add(rdoCR);

        btnGrpNewLine.add(rdoLF);
        rdoLF.setText("LF");
        rdoLF.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                rdoLFActionPerformed(evt);
            }
        });
        pnlNewLine.add(rdoLF);

        btnGrpNewLine.add(rdoCRLF);
        rdoCRLF.setText("CRLF");
        rdoCRLF.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                rdoCRLFActionPerformed(evt);
            }
        });
        pnlNewLine.add(rdoCRLF);

        pnlSelectOption.add(pnlNewLine);

        pnlWrap.setBorder(javax.swing.BorderFactory.createTitledBorder("View"));
        pnlWrap.setLayout(new java.awt.GridLayout(4, 0));

        chkViewLineWrap.setText("lineWrap");
        chkViewLineWrap.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                chkViewLineWrapActionPerformed(evt);
            }
        });
        pnlWrap.add(chkViewLineWrap);

        pnlSelectOption.add(pnlWrap);

        pnlSelect.add(pnlSelectOption, java.awt.BorderLayout.WEST);

        pnlTranslator.add(pnlSelect, java.awt.BorderLayout.NORTH);

        tabTransrator.add(pnlTranslator, java.awt.BorderLayout.CENTER);

        tabbetTranscoder.addTab("Translator", tabTransrator);

        tabGenerator.setLayout(new java.awt.BorderLayout());

        splitGenerator.setOrientation(javax.swing.JSplitPane.VERTICAL_SPLIT);

        txtGenarate.setColumns(20);
        txtGenarate.setRows(5);
        scrollGenerate.setViewportView(txtGenarate);

        splitGenerator.setBottomComponent(scrollGenerate);

        pnlTop.setLayout(new java.awt.BorderLayout());

        tabSequence.setLayout(new java.awt.BorderLayout());

        pnlGenerate.setLayout(new java.awt.BorderLayout());

        txtNumFormat.setText("%04d");
        txtNumFormat.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyPressed(java.awt.event.KeyEvent evt) {
                txtNumFormatKeyPressed(evt);
            }
        });

        lblNumFormat.setText("(c like printf format)");

        lblNumStart.setText("Start:");

        lblNumEnd.setText("End:");

        lblNumStep.setText("Stop:");

        spnNumStep.setModel(new javax.swing.SpinnerNumberModel(1, null, null, 1));

        spnNumStart.setModel(new javax.swing.SpinnerNumberModel(1, null, null, 1));

        spnNumEnd.setModel(new javax.swing.SpinnerNumberModel(100, null, null, 1));

        javax.swing.GroupLayout pnlNumbersLayout = new javax.swing.GroupLayout(pnlNumbers);
        pnlNumbers.setLayout(pnlNumbersLayout);
        pnlNumbersLayout.setHorizontalGroup(
            pnlNumbersLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlNumbersLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(pnlNumbersLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(pnlNumbersLayout.createSequentialGroup()
                        .addComponent(txtNumFormat, javax.swing.GroupLayout.PREFERRED_SIZE, 300, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(lblNumFormat, javax.swing.GroupLayout.PREFERRED_SIZE, 127, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(pnlNumbersLayout.createSequentialGroup()
                        .addGroup(pnlNumbersLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(lblNumStart)
                            .addComponent(lblNumEnd)
                            .addComponent(lblNumStep))
                        .addGap(18, 18, 18)
                        .addGroup(pnlNumbersLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(spnNumStep, javax.swing.GroupLayout.PREFERRED_SIZE, 110, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(spnNumStart, javax.swing.GroupLayout.PREFERRED_SIZE, 110, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(spnNumEnd, javax.swing.GroupLayout.PREFERRED_SIZE, 110, javax.swing.GroupLayout.PREFERRED_SIZE))))
                .addContainerGap(748, Short.MAX_VALUE))
        );
        pnlNumbersLayout.setVerticalGroup(
            pnlNumbersLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlNumbersLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(pnlNumbersLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(txtNumFormat, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(lblNumFormat))
                .addGap(13, 13, 13)
                .addGroup(pnlNumbersLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblNumStart)
                    .addComponent(spnNumStart, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(pnlNumbersLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblNumEnd)
                    .addComponent(spnNumEnd, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(9, 9, 9)
                .addGroup(pnlNumbersLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblNumStep)
                    .addComponent(spnNumStep, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(95, Short.MAX_VALUE))
        );

        tabbetSequence.addTab("Numbers", pnlNumbers);

        txtDateFormat.setText("yyyy/MM/dd");
        txtDateFormat.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                txtDateFormatActionPerformed(evt);
            }
        });
        txtDateFormat.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyPressed(java.awt.event.KeyEvent evt) {
                txtDateFormatKeyPressed(evt);
            }
        });

        lblDateFormat.setText("(DateTimeFormatter pattern)");

        lblDateStart.setText("Start:");

        lblDateEnd.setText("End:");

        lblDateStep.setText("Stop:");

        pnlDateEnd.setLayout(new java.awt.BorderLayout());

        pnlDateStart.setLayout(new java.awt.BorderLayout());

        cmbDateUnit.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "DAYS", "WEEKS", "MONTHS", "YEARS" }));

        spnDateStep.setModel(new javax.swing.SpinnerNumberModel(1, null, null, 1));

        javax.swing.GroupLayout pnlDateLayout = new javax.swing.GroupLayout(pnlDate);
        pnlDate.setLayout(pnlDateLayout);
        pnlDateLayout.setHorizontalGroup(
            pnlDateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlDateLayout.createSequentialGroup()
                .addGroup(pnlDateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(pnlDateLayout.createSequentialGroup()
                        .addContainerGap()
                        .addGroup(pnlDateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(lblDateStep)
                            .addGroup(pnlDateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, pnlDateLayout.createSequentialGroup()
                                    .addComponent(lblDateEnd)
                                    .addGap(18, 18, 18))
                                .addComponent(lblDateStart)))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(pnlDateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(pnlDateStart, javax.swing.GroupLayout.PREFERRED_SIZE, 160, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(pnlDateEnd, javax.swing.GroupLayout.PREFERRED_SIZE, 160, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addGroup(pnlDateLayout.createSequentialGroup()
                                .addComponent(spnDateStep, javax.swing.GroupLayout.PREFERRED_SIZE, 77, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(18, 18, 18)
                                .addComponent(cmbDateUnit, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))))
                    .addGroup(pnlDateLayout.createSequentialGroup()
                        .addGap(12, 12, 12)
                        .addComponent(txtDateFormat, javax.swing.GroupLayout.PREFERRED_SIZE, 300, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(lblDateFormat, javax.swing.GroupLayout.PREFERRED_SIZE, 174, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(697, Short.MAX_VALUE))
        );
        pnlDateLayout.setVerticalGroup(
            pnlDateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlDateLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(pnlDateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(txtDateFormat, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(lblDateFormat))
                .addGroup(pnlDateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(pnlDateLayout.createSequentialGroup()
                        .addGap(16, 16, 16)
                        .addComponent(lblDateStart))
                    .addGroup(pnlDateLayout.createSequentialGroup()
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(pnlDateStart, javax.swing.GroupLayout.PREFERRED_SIZE, 30, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addGroup(pnlDateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(pnlDateLayout.createSequentialGroup()
                        .addGap(16, 16, 16)
                        .addComponent(lblDateEnd))
                    .addGroup(pnlDateLayout.createSequentialGroup()
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(pnlDateEnd, javax.swing.GroupLayout.PREFERRED_SIZE, 30, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(pnlDateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(cmbDateUnit, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(pnlDateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(lblDateStep)
                        .addComponent(spnDateStep, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(85, Short.MAX_VALUE))
        );

        tabbetSequence.addTab("Date", pnlDate);

        pnlGenerate.add(tabbetSequence, java.awt.BorderLayout.CENTER);

        tabSequence.add(pnlGenerate, java.awt.BorderLayout.CENTER);

        tabbetGenerate.addTab("Sequence", tabSequence);

        pnlCharacter.setBorder(javax.swing.BorderFactory.createTitledBorder("Character"));
        pnlCharacter.setLayout(new java.awt.GridLayout(0, 1));

        chkCharacterNumber.setText("Number");
        pnlCharacter.add(chkCharacterNumber);

        chkCharacterLowerCase.setText("LowerCase");
        pnlCharacter.add(chkCharacterLowerCase);

        chkCharacterUpperCase.setText("UpperCase");
        pnlCharacter.add(chkCharacterUpperCase);

        chkCharacterSpace.setText("Space");
        pnlCharacter.add(chkCharacterSpace);

        chkCharacterUnderline.setText("Underline(_)");
        pnlCharacter.add(chkCharacterUnderline);

        pnlCustom.setLayout(new java.awt.BorderLayout());

        chkCharacterCustom.setText("Custom");
        pnlCustom.add(chkCharacterCustom, java.awt.BorderLayout.WEST);

        txtCustom.setText("!\"#$%&'()");
        txtCustom.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                txtCustomActionPerformed(evt);
            }
        });
        pnlCustom.add(txtCustom, java.awt.BorderLayout.CENTER);

        pnlCharacter.add(pnlCustom);

        pnlStringLength.setBorder(javax.swing.BorderFactory.createTitledBorder("Character length"));
        pnlStringLength.setVerifyInputWhenFocusTarget(false);
        pnlStringLength.setLayout(new javax.swing.BoxLayout(pnlStringLength, javax.swing.BoxLayout.LINE_AXIS));

        rdoRandomLengthGrp.add(rdoLength4);
        rdoLength4.setText("4");
        rdoLength4.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        pnlStringLength.add(rdoLength4);

        rdoRandomLengthGrp.add(rdoLength8);
        rdoLength8.setSelected(true);
        rdoLength8.setText("8");
        rdoLength8.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        rdoLength8.setInheritsPopupMenu(true);
        pnlStringLength.add(rdoLength8);

        rdoRandomLengthGrp.add(rdoLength16);
        rdoLength16.setText("16");
        pnlStringLength.add(rdoLength16);

        rdoRandomLengthGrp.add(rdoLengthNum);
        pnlStringLength.add(rdoLengthNum);

        spnLengthNum.setModel(new javax.swing.SpinnerNumberModel(32, 1, null, 1));
        pnlStringLength.add(spnLengthNum);

        pnlCount.setBorder(javax.swing.BorderFactory.createTitledBorder("Generate count"));
        pnlCount.setVerifyInputWhenFocusTarget(false);
        pnlCount.setLayout(new javax.swing.BoxLayout(pnlCount, javax.swing.BoxLayout.LINE_AXIS));

        rdoRandomCountGrp.add(rdoCount1);
        rdoCount1.setText("1");
        rdoCount1.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        pnlCount.add(rdoCount1);

        rdoRandomCountGrp.add(rdoCount10);
        rdoCount10.setSelected(true);
        rdoCount10.setText("10");
        rdoCount10.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        rdoCount10.setInheritsPopupMenu(true);
        pnlCount.add(rdoCount10);

        rdoRandomCountGrp.add(rdoCount50);
        rdoCount50.setText("50");
        pnlCount.add(rdoCount50);

        rdoRandomCountGrp.add(rdoCountNum);
        pnlCount.add(rdoCountNum);

        spnCountNum.setModel(new javax.swing.SpinnerNumberModel(100, 1, null, 1));
        pnlCount.add(spnCountNum);

        javax.swing.GroupLayout tabRandomLayout = new javax.swing.GroupLayout(tabRandom);
        tabRandom.setLayout(tabRandomLayout);
        tabRandomLayout.setHorizontalGroup(
            tabRandomLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(tabRandomLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(tabRandomLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(pnlCharacter, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addGroup(tabRandomLayout.createSequentialGroup()
                        .addComponent(pnlStringLength, javax.swing.GroupLayout.PREFERRED_SIZE, 240, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(pnlCount, javax.swing.GroupLayout.PREFERRED_SIZE, 240, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(698, Short.MAX_VALUE))
        );
        tabRandomLayout.setVerticalGroup(
            tabRandomLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, tabRandomLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(pnlCharacter, javax.swing.GroupLayout.PREFERRED_SIZE, 160, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(tabRandomLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(pnlCount, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(pnlStringLength, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(21, Short.MAX_VALUE))
        );

        tabbetGenerate.addTab("Random", tabRandom);

        pnlTop.add(tabbetGenerate, java.awt.BorderLayout.CENTER);

        btnGenerate.setText("generate");
        btnGenerate.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnGenerateActionPerformed(evt);
            }
        });

        txtListCopy.setText("List Copy");
        txtListCopy.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                txtListCopyActionPerformed(evt);
            }
        });

        btnSavetoFile.setText("Save to file");
        btnSavetoFile.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnSavetoFileActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout pnlRightLayout = new javax.swing.GroupLayout(pnlRight);
        pnlRight.setLayout(pnlRightLayout);
        pnlRightLayout.setHorizontalGroup(
            pnlRightLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlRightLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(pnlRightLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(txtListCopy, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(btnGenerate, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(btnSavetoFile, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap())
        );
        pnlRightLayout.setVerticalGroup(
            pnlRightLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlRightLayout.createSequentialGroup()
                .addGap(29, 29, 29)
                .addComponent(btnGenerate)
                .addGap(9, 9, 9)
                .addComponent(txtListCopy)
                .addGap(9, 9, 9)
                .addComponent(btnSavetoFile)
                .addContainerGap(156, Short.MAX_VALUE))
        );

        pnlTop.add(pnlRight, java.awt.BorderLayout.EAST);

        splitGenerator.setTopComponent(pnlTop);

        tabGenerator.add(splitGenerator, java.awt.BorderLayout.CENTER);

        tabbetTranscoder.addTab("Generater", tabGenerator);

        lblBin.setText("Bin:");

        lblOct.setText("Oct:");

        lblDec.setText("Dec:");

        lblHex.setText("Hex:");

        lblRadix32.setText("Radix32:");

        txtBin.setHorizontalAlignment(javax.swing.JTextField.RIGHT);
        txtBin.setText("0");
        txtBin.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                txtBinActionPerformed(evt);
            }
        });
        txtBin.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                txtBinKeyReleased(evt);
            }
        });

        txtOct.setHorizontalAlignment(javax.swing.JTextField.RIGHT);
        txtOct.setText("0");
        txtOct.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                txtOctKeyReleased(evt);
            }
        });

        txtDec.setHorizontalAlignment(javax.swing.JTextField.RIGHT);
        txtDec.setText("0");
        txtDec.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                txtDecKeyReleased(evt);
            }
        });

        txtHex.setHorizontalAlignment(javax.swing.JTextField.RIGHT);
        txtHex.setText("0");
        txtHex.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                txtHexActionPerformed(evt);
            }
        });
        txtHex.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                txtHexKeyReleased(evt);
            }
        });

        txtRadix32.setHorizontalAlignment(javax.swing.JTextField.RIGHT);
        txtRadix32.setText("0");
        txtRadix32.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                txtRadix32KeyReleased(evt);
            }
        });

        btnBinCopy.setText("Copy");
        btnBinCopy.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnBinCopyActionPerformed(evt);
            }
        });

        btnOctCopy.setText("Copy");
        btnOctCopy.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnOctCopyActionPerformed(evt);
            }
        });

        btnDecCopy.setText("Copy");
        btnDecCopy.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnDecCopyActionPerformed(evt);
            }
        });

        btnHexCopy.setText("Copy");
        btnHexCopy.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHexCopyActionPerformed(evt);
            }
        });

        btnRadix32Copy.setText("Copy");
        btnRadix32Copy.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnRadix32CopyActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout tabBaseBaseConverterLayout = new javax.swing.GroupLayout(tabBaseBaseConverter);
        tabBaseBaseConverter.setLayout(tabBaseBaseConverterLayout);
        tabBaseBaseConverterLayout.setHorizontalGroup(
            tabBaseBaseConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(tabBaseBaseConverterLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(tabBaseBaseConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(tabBaseBaseConverterLayout.createSequentialGroup()
                        .addGroup(tabBaseBaseConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(tabBaseBaseConverterLayout.createSequentialGroup()
                                .addComponent(lblBin, javax.swing.GroupLayout.PREFERRED_SIZE, 55, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(txtBin, javax.swing.GroupLayout.DEFAULT_SIZE, 1169, Short.MAX_VALUE))
                            .addGroup(tabBaseBaseConverterLayout.createSequentialGroup()
                                .addComponent(lblHex, javax.swing.GroupLayout.PREFERRED_SIZE, 55, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(txtHex))
                            .addGroup(tabBaseBaseConverterLayout.createSequentialGroup()
                                .addComponent(lblOct, javax.swing.GroupLayout.PREFERRED_SIZE, 55, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(txtOct))
                            .addGroup(tabBaseBaseConverterLayout.createSequentialGroup()
                                .addComponent(lblDec, javax.swing.GroupLayout.PREFERRED_SIZE, 55, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(txtDec)))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(tabBaseBaseConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(btnBinCopy, javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(btnOctCopy, javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(btnDecCopy, javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(btnHexCopy, javax.swing.GroupLayout.Alignment.TRAILING)))
                    .addGroup(tabBaseBaseConverterLayout.createSequentialGroup()
                        .addComponent(lblRadix32, javax.swing.GroupLayout.PREFERRED_SIZE, 55, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(txtRadix32)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnRadix32Copy)))
                .addContainerGap())
        );
        tabBaseBaseConverterLayout.setVerticalGroup(
            tabBaseBaseConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(tabBaseBaseConverterLayout.createSequentialGroup()
                .addGap(11, 11, 11)
                .addGroup(tabBaseBaseConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblBin)
                    .addComponent(txtBin, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(btnBinCopy))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(tabBaseBaseConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblOct)
                    .addComponent(txtOct, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(btnOctCopy))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(tabBaseBaseConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblDec)
                    .addComponent(txtDec, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(btnDecCopy))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(tabBaseBaseConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(tabBaseBaseConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(lblHex)
                        .addComponent(txtHex, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addComponent(btnHexCopy))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(tabBaseBaseConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(txtRadix32, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(lblRadix32)
                    .addComponent(btnRadix32Copy))
                .addContainerGap(819, Short.MAX_VALUE))
        );

        tabbetTranscoder.addTab("Base Converter", tabBaseBaseConverter);

        btnExport.setText("Export");
        btnExport.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnExportActionPerformed(evt);
            }
        });

        rdoConvertPEM.setSelected(true);
        rdoConvertPEM.setText("Certificate and Private key in PEM format");

        txtStoreFile.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyPressed(java.awt.event.KeyEvent evt) {
                txtStoreFileKeyPressed(evt);
            }
        });

        btnImport.setText("Import");
        btnImport.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnImportActionPerformed(evt);
            }
        });

        lblPassword.setText("Password:");

        rdoCetificateGrp.add(btnStoreTypeJKS);
        btnStoreTypeJKS.setText("JKS");
        btnStoreTypeJKS.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnStoreTypeJKSActionPerformed(evt);
            }
        });

        rdoCetificateGrp.add(btnStoreTypePKCS12);
        btnStoreTypePKCS12.setSelected(true);
        btnStoreTypePKCS12.setText("PKCS12");

        javax.swing.GroupLayout pnlCertificateLayout = new javax.swing.GroupLayout(pnlCertificate);
        pnlCertificate.setLayout(pnlCertificateLayout);
        pnlCertificateLayout.setHorizontalGroup(
            pnlCertificateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlCertificateLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(pnlCertificateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(lblPassword)
                    .addComponent(txtStorePassword, javax.swing.GroupLayout.PREFERRED_SIZE, 193, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(pnlCertificateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                        .addGroup(pnlCertificateLayout.createSequentialGroup()
                            .addComponent(rdoConvertPEM)
                            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(btnExport))
                        .addGroup(javax.swing.GroupLayout.Alignment.LEADING, pnlCertificateLayout.createSequentialGroup()
                            .addComponent(txtStoreFile, javax.swing.GroupLayout.PREFERRED_SIZE, 274, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                            .addComponent(btnImport)))
                    .addGroup(pnlCertificateLayout.createSequentialGroup()
                        .addComponent(btnStoreTypeJKS, javax.swing.GroupLayout.PREFERRED_SIZE, 64, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnStoreTypePKCS12)))
                .addContainerGap(950, Short.MAX_VALUE))
        );
        pnlCertificateLayout.setVerticalGroup(
            pnlCertificateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlCertificateLayout.createSequentialGroup()
                .addGap(20, 20, 20)
                .addGroup(pnlCertificateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(btnStoreTypeJKS)
                    .addComponent(btnStoreTypePKCS12))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(pnlCertificateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(txtStoreFile, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(btnImport))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(lblPassword)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(txtStorePassword, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addGroup(pnlCertificateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(rdoConvertPEM)
                    .addComponent(btnExport))
                .addContainerGap(755, Short.MAX_VALUE))
        );

        tabbetTranscoder.addTab("Certificate", pnlCertificate);

        txtTokenList.setColumns(20);
        txtTokenList.setRows(5);
        jScrollPane1.setViewportView(txtTokenList);

        txtBase.setText("0");

        txtExponent.setText("0");

        txtStrength.setText("0");

        btnCalc.setText("Calc");
        btnCalc.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnCalcActionPerformed(evt);
            }
        });

        jLabel1.setText("bit");

        jLabel2.setText(" Character kind");

        jLabel3.setText("length");

        jLabel4.setText("stlength");

        btnAnalyze.setText("Analyze");
        btnAnalyze.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnAnalyzeActionPerformed(evt);
            }
        });

        lblmaximum.setText("maximum");

        javax.swing.GroupLayout tabTokenStrengthLayout = new javax.swing.GroupLayout(tabTokenStrength);
        tabTokenStrength.setLayout(tabTokenStrengthLayout);
        tabTokenStrengthLayout.setHorizontalGroup(
            tabTokenStrengthLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(tabTokenStrengthLayout.createSequentialGroup()
                .addGap(22, 22, 22)
                .addGroup(tabTokenStrengthLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(tabTokenStrengthLayout.createSequentialGroup()
                        .addGroup(tabTokenStrengthLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                            .addComponent(jLabel2, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(txtBase, javax.swing.GroupLayout.Alignment.LEADING))
                        .addGap(39, 39, 39)
                        .addGroup(tabTokenStrengthLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel4, javax.swing.GroupLayout.PREFERRED_SIZE, 81, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addGroup(tabTokenStrengthLayout.createSequentialGroup()
                                .addComponent(txtExponent, javax.swing.GroupLayout.PREFERRED_SIZE, 72, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(lblmaximum, javax.swing.GroupLayout.PREFERRED_SIZE, 57, javax.swing.GroupLayout.PREFERRED_SIZE)))
                        .addGap(20, 20, 20)
                        .addGroup(tabTokenStrengthLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(tabTokenStrengthLayout.createSequentialGroup()
                                .addComponent(txtStrength, javax.swing.GroupLayout.PREFERRED_SIZE, 81, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 44, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(btnCalc)
                                .addGap(0, 0, Short.MAX_VALUE))
                            .addComponent(jLabel3, javax.swing.GroupLayout.DEFAULT_SIZE, 342, Short.MAX_VALUE))
                        .addGap(671, 671, 671))
                    .addGroup(tabTokenStrengthLayout.createSequentialGroup()
                        .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 558, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnAnalyze)
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))))
        );
        tabTokenStrengthLayout.setVerticalGroup(
            tabTokenStrengthLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(tabTokenStrengthLayout.createSequentialGroup()
                .addGap(22, 22, 22)
                .addGroup(tabTokenStrengthLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 196, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(btnAnalyze))
                .addGap(18, 18, 18)
                .addGroup(tabTokenStrengthLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(tabTokenStrengthLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(jLabel4)
                        .addComponent(jLabel2))
                    .addComponent(jLabel3))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(tabTokenStrengthLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(txtBase, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(tabTokenStrengthLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(txtStrength, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(btnCalc)
                        .addComponent(txtExponent, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(lblmaximum)
                        .addComponent(jLabel1)))
                .addContainerGap(638, Short.MAX_VALUE))
        );

        tabbetTranscoder.addTab("Token strength", tabTokenStrength);

        add(tabbetTranscoder, java.awt.BorderLayout.CENTER);
    }// </editor-fold>//GEN-END:initComponents

    @Override
    public String getTabCaption() {
        return "JTransCoder";
    }

    @Override
    public Component getUiComponent() {
        return this;
    }

    private CustomTableModel modelHex = null;

    private JDatePickerImpl datePickerStart;
    private JDatePickerImpl datePickerEnd;

    private final HexViewTab hexInputViewTab = new HexViewTab();
    private final HexViewTab hexOutputViewTab = new HexViewTab();

    private final javax.swing.JPanel pnlOutputFormat = new javax.swing.JPanel();

    /*
     * ステータスメッセージ書式
     */
    private static final MessageFormat STATUS_TEXT_FORMAT = new MessageFormat(
            "Length:{0,number} Position:{1,number} SelectLength:{2,number}"); // @jve:decl-index=0:

    protected final java.util.ResourceBundle BUNDLE = java.util.ResourceBundle.getBundle("yagura/resources/Resource");

    private void txtNumFormatKeyPressed(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_txtNumFormatKeyPressed
        //this.lblExampleValue.setText(String.format(this.txtFormat.getText(), 123));
    }//GEN-LAST:event_txtNumFormatKeyPressed

    private void rdoAlphaNumActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rdoAlphaNumActionPerformed
        firePropertyChange(TabbetOption.JTRANS_CODER_PROPERTY, null, this.getProperty());
    }//GEN-LAST:event_rdoAlphaNumActionPerformed

    private void btnSmartDecodeActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnSmartDecodeActionPerformed
        this.toSmartDecode(this.getInputText());
    }//GEN-LAST:event_btnSmartDecodeActionPerformed

    private void btnEncodeActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnEncodeActionPerformed
        try {
            String value = this.getInputText();
            String encode = value;
            if (this.rdoUrl.isSelected()) {
                encode = TransUtil.encodeUrl(value, this.getSelectEncode(), TransUtil.getEncodeTypePattern(this.getEncodeType()), this.rdoUpperCase.isSelected());
            } else if (this.rdoUrlUnicode.isSelected()) {
                encode = TransUtil.toUnocodeUrlEncode(value, TransUtil.getEncodeTypePattern(this.getEncodeType()), this.rdoUpperCase.isSelected());
                if (this.rdoUpperCase.isSelected()) {
                    encode = encode.toUpperCase();
                }
            } else if (this.rdoBase64.isSelected()) {
                encode = TransUtil.toBase64Encode(value, this.getSelectEncode(), this.chkPadding.isSelected());
                if (this.chk76Newline.isSelected()) {
                    if (!this.chkRawMode.isSelected()) {
                        encode = TransUtil.newLine(TransUtil.getNewLine(this.getSelectNewLine()), encode, 76);
                    }
                } else if (this.chk64Newline.isSelected()) {
                    if (!this.chkRawMode.isSelected()) {
                        encode = TransUtil.newLine(TransUtil.getNewLine(this.getSelectNewLine()), encode, 64);
                    }
                }
            } else if (this.rdoBase64URLSafe.isSelected()) {
                encode = TransUtil.toBase64URLSafeEncode(value, this.getSelectEncode());
                if (this.chk76Newline.isSelected()) {
                    if (!this.chkRawMode.isSelected()) {
                        encode = TransUtil.newLine(TransUtil.getNewLine(this.getSelectNewLine()), encode, 76);
                    }
                } else if (this.chk64Newline.isSelected()) {
                    if (!this.chkRawMode.isSelected()) {
                        encode = TransUtil.newLine(TransUtil.getNewLine(this.getSelectNewLine()), encode, 64);
                    }
                }
            } else if (this.rdoBase32.isSelected()) {
                encode = TransUtil.toBase32Encode(value, this.getSelectEncode(), this.chkNPadding.isSelected());
            } else if (this.rdoBase16.isSelected()) {
                encode = TransUtil.toBase16Encode(value, this.getSelectEncode(), this.chkNPadding.isSelected());
//            } else if (this.rdoUuencode.isSelected()) {
//                encode = TransUtil.toUuencode(value, this.getSelectEncode());
            } else if (this.rdoQuotedPrintable.isSelected()) {
                encode = TransUtil.toQuotedPrintable(value, this.getSelectEncode());
            } else if (this.rdoPunycode.isSelected()) {
                encode = TransUtil.toPunycodeEncode(value);
            } else if (this.rdoHtml.isSelected()) {
                encode = HttpUtil.toHtmlEncode(value);
            } else if (this.rdoUnicodeHex.isSelected()) {
                encode = TransUtil.toUnocodeEncode(value, TransUtil.getEncodeTypePattern(this.getEncodeType()), this.rdoUpperCase.isSelected());
            } else if (this.rdoByteHex.isSelected()) {
                encode = TransUtil.toByteHexEncode(value, this.getSelectEncode(), TransUtil.getEncodeTypePattern(this.getEncodeType()), this.rdoUpperCase.isSelected());
            } else if (this.rdoByteHex2.isSelected()) {
                encode = TransUtil.toByteHex2Encode(value, this.getSelectEncode(), TransUtil.getEncodeTypePattern(this.getEncodeType()), this.rdoUpperCase.isSelected());
            } else if (this.rdoByteOct.isSelected()) {
                encode = TransUtil.toByteOctEncode(value, this.getSelectEncode(), TransUtil.getEncodeTypePattern(this.getEncodeType()));
            } else if (this.rdoHtmlDec.isSelected()) {
                encode = TransUtil.toHtmlDecEncode(value, TransUtil.getEncodeTypePattern(this.getEncodeType()));
            } else if (this.rdoHtmlHex.isSelected()) {
                encode = TransUtil.toHtmlHexEncode(value, TransUtil.getEncodeTypePattern(this.getEncodeType()), this.rdoUpperCase.isSelected());
            } else if (this.rdoHtmlByteHex.isSelected()) {
                encode = TransUtil.toHtmlByteHexEncode(value, this.getSelectEncode(), TransUtil.getEncodeTypePattern(this.getEncodeType()), this.rdoUpperCase.isSelected());
            } else if (this.rdoGzip.isSelected()) {
                encode = Util.getRawStr(ConvertUtil.compressGzip(Util.encodeMessage(value, this.getSelectEncode())));
            } else if (this.rdoZLIB.isSelected()) {
                encode = Util.getRawStr(ConvertUtil.compressZlib(Util.encodeMessage(value, this.getSelectEncode())));
            } else if (this.rdoUTF7.isSelected()) {
                encode = TransUtil.toUTF7Encode(value);
            } else if (this.rdoILLUTF8.isSelected()) {
                String byteUTF8 = (String) this.cmbIILUTF8.getSelectedItem();
                byte[] out_byte = TransUtil.UTF8Encode(value, Util.parseIntDefault(byteUTF8, 2));
                StringBuilder buff = new StringBuilder();
                for (byte b : out_byte) {
                    if (this.rdoUpperCase.isSelected()) {
                        buff.append(String.format("%%%X", b));
                    } else {
                        buff.append(String.format("%%%x", b));
                    }
                }
                encode = buff.toString();
            } else if (this.rdoCLang.isSelected()) {
                encode = TransUtil.encodeCLangQuote(encode);
            } else if (this.rdoSQLLang.isSelected()) {
                encode = TransUtil.encodeSQLLangQuote(encode);
            } else if (this.rdoCLang.isSelected()) {
                encode = TransUtil.encodeCLangQuote(encode);
            } else if (this.rdoSQLLang.isSelected()) {
                encode = TransUtil.encodeSQLLangQuote(encode);
            } else if (this.rdoRegex.isSelected()) {
                encode = TransUtil.toRegexEncode(encode);
            }
            this.setOutput(encode);
        } catch (Exception ex) {
            this.setOutputText(Util.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, null, ex);
        }
    }//GEN-LAST:event_btnEncodeActionPerformed

    private void btnDecodeActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnDecodeActionPerformed
        TransUtil.EncodePattern encodePattern = null;
        if (this.rdoUrl.isSelected()) {
            encodePattern = TransUtil.EncodePattern.URL_STANDARD;
        } else if (this.rdoUrlUnicode.isSelected()) {
            encodePattern = TransUtil.EncodePattern.URL_UNICODE;
        } else if (this.rdoBase64.isSelected()) {
            encodePattern = TransUtil.EncodePattern.BASE64;
        } else if (this.rdoBase64URLSafe.isSelected()) {
            encodePattern = TransUtil.EncodePattern.BASE64_URLSAFE;
        } else if (this.rdoBase32.isSelected()) {
            encodePattern = TransUtil.EncodePattern.BASE32;
        } else if (this.rdoBase16.isSelected()) {
            encodePattern = TransUtil.EncodePattern.BASE16;
//        } else if (this.rdoUuencode.isSelected()) {
//            encodePattern = TransUtil.EncodePattern.UUENCODE;
        } else if (this.rdoQuotedPrintable.isSelected()) {
            encodePattern = TransUtil.EncodePattern.QUOTEDPRINTABLE;
        } else if (this.rdoPunycode.isSelected()) {
            encodePattern = TransUtil.EncodePattern.PUNYCODE;
        } else if (this.rdoHtml.isSelected()) {
            encodePattern = TransUtil.EncodePattern.HTML;
        } else if (this.rdoUnicodeHex.isSelected()) {
            encodePattern = TransUtil.EncodePattern.UNICODE;
        } else if (this.rdoByteHex.isSelected()) {
            encodePattern = TransUtil.EncodePattern.BYTE_HEX;
        } else if (this.rdoByteHex2.isSelected()) {
            encodePattern = TransUtil.EncodePattern.BYTE_HEX2;
        } else if (this.rdoByteOct.isSelected()) {
            encodePattern = TransUtil.EncodePattern.BYTE_OCT;
        } else if (this.rdoHtmlDec.isSelected()) {
            encodePattern = TransUtil.EncodePattern.HTML;
        } else if (this.rdoHtmlByteHex.isSelected()) {
            encodePattern = TransUtil.EncodePattern.BYTE_HTML;
        } else if (this.rdoHtmlHex.isSelected()) {
            encodePattern = TransUtil.EncodePattern.HTML;
        } else if (this.rdoGzip.isSelected()) {
            encodePattern = TransUtil.EncodePattern.GZIP;
        } else if (this.rdoZLIB.isSelected()) {
            encodePattern = TransUtil.EncodePattern.ZLIB;
        } else if (this.rdoUTF7.isSelected()) {
            encodePattern = TransUtil.EncodePattern.UTF7;
        } else if (this.rdoILLUTF8.isSelected()) {
            encodePattern = TransUtil.EncodePattern.UTF8_ILL;
        } else if (this.rdoCLang.isSelected()) {
            encodePattern = TransUtil.EncodePattern.C_LANG;
        } else if (this.rdoSQLLang.isSelected()) {
            encodePattern = TransUtil.EncodePattern.SQL_LANG;
        } else if (this.rdoRegex.isSelected()) {
            encodePattern = TransUtil.EncodePattern.REGEX;
        }
        this.toSmartDecode(this.getInputText(), encodePattern);
    }//GEN-LAST:event_btnDecodeActionPerformed

    private int getCaretCodePoint(javax.swing.JTextArea textArea) {
        String caretstrs = this.getCaretString(textArea);
        if (caretstrs.length() == 0) {
            return 0;
        } else {
            return caretstrs.codePointAt(0);
        }
    }

    private String getCaretString(javax.swing.JTextArea textArea) {
        int caretPos = textArea.getCaret().getDot();
        String text = textArea.getText();
        if (caretPos == text.length()) {
            return "";
        } else {
            return text.substring(caretPos, text.offsetByCodePoints(caretPos, 1));
        }
    }

    private void doStateDecodeChange() {
        this.btnDecode.setEnabled(!(this.rdoILLUTF8.isSelected()));
        this.cmbIILUTF8.setEnabled(this.rdoILLUTF8.isSelected());
    }

    private void rdoILLUTF8StateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_rdoILLUTF8StateChanged
        this.doStateDecodeChange();
    }//GEN-LAST:event_rdoILLUTF8StateChanged

    private void btnHashMd2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashMd2ActionPerformed
        try {
            String inputText = TransUtil.toMd2Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException e1) {
            this.setOutputText(Util.getStackTraceMessage(e1));
            logger.log(Level.SEVERE, null, e1);
        }
    }//GEN-LAST:event_btnHashMd2ActionPerformed

    private void btnHashMd5ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashMd5ActionPerformed
        try {
            String inputText = TransUtil.toMd5Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException e1) {
            this.setOutputText(Util.getStackTraceMessage(e1));
            logger.log(Level.SEVERE, null, e1);
        }
    }//GEN-LAST:event_btnHashMd5ActionPerformed

    private void btnHashSha1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashSha1ActionPerformed
        try {
            String inputText = TransUtil.toSHA1Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException e1) {
            this.setOutputText(Util.getStackTraceMessage(e1));
            logger.log(Level.SEVERE, null, e1);
        }
    }//GEN-LAST:event_btnHashSha1ActionPerformed

    private void btnHashSha256ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashSha256ActionPerformed
        try {
            String inputText = TransUtil.toSHA256Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException e1) {
            this.setOutputText(Util.getStackTraceMessage(e1));
            logger.log(Level.SEVERE, null, e1);
        }
    }//GEN-LAST:event_btnHashSha256ActionPerformed

    private void btnHashSha384ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashSha384ActionPerformed
        try {
            String inputText = TransUtil.toSHA384Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException e1) {
            this.setOutputText(Util.getStackTraceMessage(e1));
            logger.log(Level.SEVERE, null, e1);
        }
    }//GEN-LAST:event_btnHashSha384ActionPerformed

    private void btnHashSha512ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashSha512ActionPerformed
        try {
            String inputText = TransUtil.toSHA512Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException e1) {
            this.setOutputText(Util.getStackTraceMessage(e1));
            logger.log(Level.SEVERE, null, e1);
        }
    }//GEN-LAST:event_btnHashSha512ActionPerformed

    private void rdoCRLFActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rdoCRLFActionPerformed
        firePropertyChange(TabbetOption.JTRANS_CODER_PROPERTY, null, this.getProperty());
    }//GEN-LAST:event_rdoCRLFActionPerformed

    private void btnOutputfileActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnOutputfileActionPerformed
        JFileChooser filechooser = new JFileChooser();
        filechooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        int selected = filechooser.showSaveDialog(this);
        if (selected == JFileChooser.APPROVE_OPTION) {
            try {
                File file = filechooser.getSelectedFile();
                byte[] output = this.getOutputByte();
                Util.bytesToFile(output, file);
            } catch (IOException ex) {
                logger.log(Level.SEVERE, null, ex);
            }
        }
    }//GEN-LAST:event_btnOutputfileActionPerformed

    private void rdoLigthActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rdoLigthActionPerformed
        firePropertyChange(TabbetOption.JTRANS_CODER_PROPERTY, null, this.getProperty());
    }//GEN-LAST:event_rdoLigthActionPerformed

    private void txtCustomActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_txtCustomActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_txtCustomActionPerformed

    private void btnOutputToInputActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnOutputToInputActionPerformed
        String outputText = this.getOutputText();
        byte[] outputByte = this.getOutputByte();
        this.clearText();
        this.setInputText(outputText);
        this.setInputByte(outputByte);
    }//GEN-LAST:event_btnOutputToInputActionPerformed

    private void rdoQuotedPrintableActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rdoQuotedPrintableActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_rdoQuotedPrintableActionPerformed

    private void rdoStandardActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rdoStandardActionPerformed
        firePropertyChange(TabbetOption.JTRANS_CODER_PROPERTY, null, this.getProperty());
    }//GEN-LAST:event_rdoStandardActionPerformed

    private void rdoLowerCaseActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rdoLowerCaseActionPerformed
        firePropertyChange(TabbetOption.JTRANS_CODER_PROPERTY, null, this.getProperty());
    }//GEN-LAST:event_rdoLowerCaseActionPerformed

    private void btnCalcActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnCalcActionPerformed
        int base = Util.parseIntDefault(this.txtBase.getText(), 0);
        int exponent = Util.parseIntDefault(this.txtExponent.getText(), 0);
        this.txtStrength.setText(String.format("%4.2f", calcStlength(base, exponent)));
    }//GEN-LAST:event_btnCalcActionPerformed

    private void btnAnalyzeActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnAnalyzeActionPerformed
        String[] tokenList = this.txtTokenList.getText().split("\n");
        HashSet<Character> map = new HashSet<>();
        int sum_len = 0;
        for (int i = 0; i < tokenList.length; i++) {
            sum_len += tokenList[i].length();
            for (int j = 0; j < tokenList[i].length(); j++) {
                char c = tokenList[i].charAt(j);
                map.add(c);
            }
        }
        this.txtBase.setText(Util.toString(map.toArray().length));
        this.txtExponent.setText(Util.toString(sum_len / tokenList.length));
        this.btnCalcActionPerformed(evt);
    }//GEN-LAST:event_btnAnalyzeActionPerformed

    private void btnInputfileActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnInputfileActionPerformed
        JFileChooser filechooser = new JFileChooser();
        filechooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        int selected = filechooser.showOpenDialog(this);
        if (selected == JFileChooser.APPROVE_OPTION) {
            try {
                File file = filechooser.getSelectedFile();
                byte[] input = Util.bytesFromFile(file);
                this.setInputText(Util.getRawStr(input));
                this.setInputByte(input);
            } catch (IOException ex) {
                logger.log(Level.SEVERE, null, ex);
            }
        }
    }//GEN-LAST:event_btnInputfileActionPerformed

    private void tabbetInputStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_tabbetInputStateChanged
        if (this.txtInputRaw == null) return;
        if (this.chkRawMode.isSelected()) {
            this.setInputByte(Util.getRawByte(this.txtInputRaw.getText()));
        } else {
            this.setInputByte(Util.getRawByte(TransUtil.replaceNewLine(getSelectNewLine(), this.txtInputRaw.getText())));
        }
    }//GEN-LAST:event_tabbetInputStateChanged

    private void btnClearActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnClearActionPerformed
        this.clearText();
    }//GEN-LAST:event_btnClearActionPerformed

    private void btnImportActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnImportActionPerformed
        JFileChooser filechooser = new JFileChooser();
        filechooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        int selected = filechooser.showOpenDialog(this);
        if (selected == JFileChooser.APPROVE_OPTION) {
            File file = filechooser.getSelectedFile();
            this.txtStoreFile.setText(file.getAbsolutePath());
        }
    }//GEN-LAST:event_btnImportActionPerformed

    private void txtStoreFileKeyPressed(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_txtStoreFileKeyPressed
    }//GEN-LAST:event_txtStoreFileKeyPressed

    private void btnExportActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnExportActionPerformed
        try {
            HashMap<String, Map.Entry<Key, X509Certificate>> mapCert = null;
            File storeFile = new File(this.txtStoreFile.getText());
            if (this.rdoConvertPEM.isSelected()) {
                if (this.btnStoreTypeJKS.isSelected()) {
                    mapCert = CertUtil.loadFromJKS(storeFile, this.txtStorePassword.getText());
                } else {
                    mapCert = CertUtil.loadFromPKCS12(storeFile, this.txtStorePassword.getText());
                }
            }
            for (String ailias : mapCert.keySet()) {
                Map.Entry<Key, X509Certificate> cert = mapCert.get(ailias);
                JFileChooser filechooser = new JFileChooser();
                filechooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
                int selected = filechooser.showSaveDialog(this);
                if (selected == JFileChooser.APPROVE_OPTION) {
                    File pemFile = filechooser.getSelectedFile();
                    String output = CertUtil.exportToPem(cert.getKey(), cert.getValue());
                    Util.bytesToFile(Util.getRawByte(output), pemFile);
                }
                break;
            }
        } catch (CertificateEncodingException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(), "JTransCoder", JOptionPane.INFORMATION_MESSAGE);
        } catch (UnrecoverableKeyException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(), "JTransCoder", JOptionPane.INFORMATION_MESSAGE);
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(), "JTransCoder", JOptionPane.INFORMATION_MESSAGE);
        }
    }//GEN-LAST:event_btnExportActionPerformed

    private void btnStoreTypeJKSActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnStoreTypeJKSActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_btnStoreTypeJKSActionPerformed

    private void chk64NewlineActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_chk64NewlineActionPerformed
        if (this.chk64Newline.isSelected()) {
            this.chk76Newline.setSelected(false);
        }
    }//GEN-LAST:event_chk64NewlineActionPerformed

    private void chk76NewlineActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_chk76NewlineActionPerformed
        if (this.chk76Newline.isSelected()) {
            this.chk64Newline.setSelected(false);
        }
    }//GEN-LAST:event_chk76NewlineActionPerformed

    private void rdoAllActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rdoAllActionPerformed
        firePropertyChange(TabbetOption.JTRANS_CODER_PROPERTY, null, this.getProperty());
    }//GEN-LAST:event_rdoAllActionPerformed

    private void rdoUpperCaseActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rdoUpperCaseActionPerformed
        firePropertyChange(TabbetOption.JTRANS_CODER_PROPERTY, null, this.getProperty());
    }//GEN-LAST:event_rdoUpperCaseActionPerformed

    private void rdoNoneActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rdoNoneActionPerformed
        firePropertyChange(TabbetOption.JTRANS_CODER_PROPERTY, null, this.getProperty());
    }//GEN-LAST:event_rdoNoneActionPerformed

    private void rdoCRActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rdoCRActionPerformed
        firePropertyChange(TabbetOption.JTRANS_CODER_PROPERTY, null, this.getProperty());
    }//GEN-LAST:event_rdoCRActionPerformed

    private void rdoLFActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rdoLFActionPerformed
        firePropertyChange(TabbetOption.JTRANS_CODER_PROPERTY, null, this.getProperty());
    }//GEN-LAST:event_rdoLFActionPerformed

    private void chkViewLineWrapActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_chkViewLineWrapActionPerformed
        this.txtInputRaw.setLineWrap(this.chkViewLineWrap.isSelected());
        this.txtOutputRaw.setLineWrap(this.chkViewLineWrap.isSelected());
        if (evt != null) {
            firePropertyChange(TabbetOption.JTRANS_CODER_PROPERTY, null, this.getProperty());
        }
    }//GEN-LAST:event_chkViewLineWrapActionPerformed

    private void chkRawModeActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_chkRawModeActionPerformed
        this.cmbEncoding.setEnabled(!(this.chkRawMode.isSelected() || this.chkGuess.isSelected()));
        SwingUtil.setContainerEnable(this.pnlNewLine, !this.chkRawMode.isSelected());
        if (evt != null) {
            firePropertyChange(TabbetOption.JTRANS_CODER_PROPERTY, null, this.getProperty());
        }
    }//GEN-LAST:event_chkRawModeActionPerformed

    private void chkGuessActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_chkGuessActionPerformed
        this.chkRawMode.setEnabled(!this.chkGuess.isSelected());
        this.cmbEncoding.setEnabled(!(this.chkRawMode.isSelected() || this.chkGuess.isSelected()));
        if (evt != null) {
            firePropertyChange(TabbetOption.JTRANS_CODER_PROPERTY, null, this.getProperty());
        }
    }//GEN-LAST:event_chkGuessActionPerformed

    private void cmbEncodingActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cmbEncodingActionPerformed
        firePropertyChange(TabbetOption.JTRANS_CODER_PROPERTY, null, this.getProperty());
    }//GEN-LAST:event_cmbEncodingActionPerformed

    private void txtDateFormatKeyPressed(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_txtDateFormatKeyPressed
        // TODO add your handling code here:
    }//GEN-LAST:event_txtDateFormatKeyPressed

    private void btnGenerateActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnGenerateActionPerformed
        if (this.tabbetGenerate.getSelectedIndex() == this.tabbetGenerate.indexOfTab("Sequence")) {
            if (this.tabbetSequence.getSelectedIndex() == this.tabbetSequence.indexOfTab("Numbers")) {
                try {
                    final String numFormat = this.txtNumFormat.getText();
                    final int startNum = (Integer) this.spnNumStart.getModel().getValue();
                    final int endNum = (Integer) this.spnNumEnd.getModel().getValue();
                    final int stepNum = (Integer) this.spnNumStep.getValue();
                    SwingWorker swList = new SwingWorker<String, Object>() {
                        @Override
                        protected String doInBackground() throws Exception {
                            String[] list = TransUtil.generaterList(numFormat, startNum, endNum, stepNum);
                            return TransUtil.join("\r\n", list);
                        }

                        protected void process(List<Object> chunks) {
                        }

                        protected void done() {
                            try {
                                txtGenarate.setText(get());
                            } catch (InterruptedException ex) {
                                logger.log(Level.SEVERE, null, ex);
                            } catch (ExecutionException ex) {
                                logger.log(Level.SEVERE, null, ex);
                            }
                        }
                    };
                    swList.execute();

                } catch (IllegalFormatException e) {
                    JOptionPane.showMessageDialog(this, BUNDLE.getString("view.transcoder.format.error"), "JTranscoder", JOptionPane.INFORMATION_MESSAGE);
                } catch (IllegalArgumentException e) {
                    JOptionPane.showMessageDialog(this, e.getMessage(), "JTranscoder", JOptionPane.INFORMATION_MESSAGE);
                }
            } else if (this.tabbetSequence.getSelectedIndex() == this.tabbetSequence.indexOfTab("Date")) {
                try {
                    final String numFormat = this.txtDateFormat.getText();
                    final LocalDate dateStart = LocalDate.of(datePickerStart.getModel().getYear(), datePickerStart.getModel().getMonth() + 1, datePickerStart.getModel().getDay());
                    final LocalDate dateEnd = LocalDate.of(datePickerEnd.getModel().getYear(), datePickerEnd.getModel().getMonth() + 1, datePickerEnd.getModel().getDay());;
                    final int stepNum = (Integer) this.spnDateStep.getModel().getValue();
                    final String dateUnit = (String) this.cmbDateUnit.getSelectedItem();

                    SwingWorker swList = new SwingWorker<String, Object>() {
                        @Override
                        protected String doInBackground() throws Exception {
                            DateUnit unit = Enum.valueOf(DateUnit.class, dateUnit);
                            String[] list = TransUtil.dateList(numFormat, dateStart, dateEnd, stepNum, unit);
                            return TransUtil.join("\r\n", list);
                        }

                        protected void process(List<Object> chunks) {
                        }

                        protected void done() {
                            try {
                                txtGenarate.setText(get());
                            } catch (InterruptedException ex) {
                                logger.log(Level.SEVERE, null, ex);
                            } catch (ExecutionException ex) {
                                logger.log(Level.SEVERE, null, ex);
                            }
                        }
                    };
                    swList.execute();

                } catch (IllegalFormatException e) {
                    JOptionPane.showMessageDialog(this, BUNDLE.getString("view.transcoder.format.error"), "JTranscoder", JOptionPane.INFORMATION_MESSAGE);
                } catch (IllegalArgumentException e) {
                    JOptionPane.showMessageDialog(this, e.getMessage(), "JTranscoder", JOptionPane.INFORMATION_MESSAGE);
                }
            }
        } else if (this.tabbetGenerate.getSelectedIndex() == this.tabbetGenerate.indexOfTab("Random")) {
            final int count = this.getGenerateCount();
            final int length = this.getCharacterLength();
            final String rangeChars = this.getRangeChars();
            if (rangeChars.length() == 0) {
                JOptionPane.showMessageDialog(this, BUNDLE.getString("view.transcoder.chars.empty"), "JTranscoder", JOptionPane.INFORMATION_MESSAGE);
            } else {
                SwingWorker swList = new SwingWorker<String, Object>() {
                    @Override
                    protected String doInBackground() throws Exception {
                        String[] list = TransUtil.randomList(rangeChars, length, count);
                        return TransUtil.join("\r\n", list);
                    }

                    protected void process(List<Object> chunks) {
                    }

                    protected void done() {
                        try {
                            txtGenarate.setText(get());
                        } catch (InterruptedException ex) {
                            logger.log(Level.SEVERE, null, ex);
                        } catch (ExecutionException ex) {
                            logger.log(Level.SEVERE, null, ex);
                        }
                    }
                };
                swList.execute();
            }
        }
    }//GEN-LAST:event_btnGenerateActionPerformed

    private void txtListCopyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_txtListCopyActionPerformed
        String s = this.txtGenarate.getText();
        SwingUtil.systemClipboardCopy(s);
    }//GEN-LAST:event_txtListCopyActionPerformed

    private void btnSavetoFileActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnSavetoFileActionPerformed
        String s = this.txtGenarate.getText();
        JFileChooser filechooser = new JFileChooser();
        filechooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        int selected = filechooser.showSaveDialog(null);
        if (selected == JFileChooser.APPROVE_OPTION) {
            File file = filechooser.getSelectedFile();
            if (SwingUtil.isFileOverwriteConfirmed(file, String.format(BUNDLE.getString("extend.exists.overwrite.message"), file.getName()), BUNDLE.getString("extend.exists.overwrite.confirm"))) {
                try ( BufferedOutputStream fstm = new BufferedOutputStream(new FileOutputStream(file))) {
                    fstm.write(Util.encodeMessage(s, this.getSelectEncode()));
                } catch (Exception ex) {
                    logger.log(Level.SEVERE, null, ex);
                }
            }
        }
    }//GEN-LAST:event_btnSavetoFileActionPerformed

    private void txtDateFormatActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_txtDateFormatActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_txtDateFormatActionPerformed

    private void rdoByteHexActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rdoByteHexActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_rdoByteHexActionPerformed

    private void rdoByteOctActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rdoByteOctActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_rdoByteOctActionPerformed

    private void btnSmartMatchActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnSmartMatchActionPerformed
        try {
            String enc = (this.chkWithByte.isSelected()) ? this.getSelectEncode() : null;
            String inputText = TransUtil.toSmartMatch(getInputText(), enc);
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException e1) {
            this.setOutputText(Util.getStackTraceMessage(e1));
            logger.log(Level.SEVERE, null, e1);
        }
    }//GEN-LAST:event_btnSmartMatchActionPerformed

    private void btnOutputCopyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnOutputCopyActionPerformed
        SwingUtil.systemClipboardCopy(this.txtOutputRaw.getText());
    }//GEN-LAST:event_btnOutputCopyActionPerformed

    private void rdoHtmlHexActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rdoHtmlHexActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_rdoHtmlHexActionPerformed

    private void rdoHtmlByteHexActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rdoHtmlByteHexActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_rdoHtmlByteHexActionPerformed

    private void btnCRC32ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnCRC32ActionPerformed
        try {
            String inputText = Long.toString(HashUtil.toCRC32Sum(getInputText(), this.getSelectEncode()));
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException e1) {
            this.setOutputText(Util.getStackTraceMessage(e1));
            logger.log(Level.SEVERE, null, e1);
        }
    }//GEN-LAST:event_btnCRC32ActionPerformed

    private void btnAdler32ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnAdler32ActionPerformed
        try {
            String inputText = Long.toString(HashUtil.toAdler32Sum(getInputText(), this.getSelectEncode()));
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException e1) {
            this.setOutputText(Util.getStackTraceMessage(e1));
            logger.log(Level.SEVERE, null, e1);
        }
    }//GEN-LAST:event_btnAdler32ActionPerformed

    private void rdoRegexStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_rdoRegexStateChanged
        this.doStateDecodeChange();
    }//GEN-LAST:event_rdoRegexStateChanged

    private void btnSmartFormatActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnSmartFormatActionPerformed
        this.toSmartDecode(this.getInputText(), TransUtil.EncodePattern.NONE);
    }//GEN-LAST:event_btnSmartFormatActionPerformed

    private void rdoMinifyFormatActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rdoMinifyFormatActionPerformed
    }//GEN-LAST:event_rdoMinifyFormatActionPerformed

    private void rdoBeautifyFormatActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rdoBeautifyFormatActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_rdoBeautifyFormatActionPerformed

    private void txtBinKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_txtBinKeyReleased
        BigInteger value = BIN_DOC.getValue();
        this.txtOct.setText(value.toString(8));
        this.txtDec.setText(value.toString(10));
        this.txtHex.setText(value.toString(16));
        this.txtRadix32.setText(value.toString(32));
    }//GEN-LAST:event_txtBinKeyReleased

    private void txtOctKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_txtOctKeyReleased
        BigInteger value = OCT_DOC.getValue();
        this.txtBin.setText(value.toString(2));
        this.txtDec.setText(value.toString(10));
        this.txtHex.setText(value.toString(16));
        this.txtRadix32.setText(value.toString(32));
    }//GEN-LAST:event_txtOctKeyReleased

    private void txtDecKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_txtDecKeyReleased
        BigInteger value = DEC_DOC.getValue();
        this.txtBin.setText(value.toString(2));
        this.txtOct.setText(value.toString(8));
        this.txtHex.setText(value.toString(16));
        this.txtRadix32.setText(value.toString(32));
    }//GEN-LAST:event_txtDecKeyReleased

    private void txtHexKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_txtHexKeyReleased
        BigInteger value = HEX_DOC.getValue();
        this.txtBin.setText(value.toString(2));
        this.txtOct.setText(value.toString(8));
        this.txtDec.setText(value.toString(10));
        this.txtRadix32.setText(value.toString(32));
    }//GEN-LAST:event_txtHexKeyReleased

    private void btnBinCopyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnBinCopyActionPerformed
        SwingUtil.systemClipboardCopy(this.txtBin.getText());
    }//GEN-LAST:event_btnBinCopyActionPerformed

    private void btnOctCopyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnOctCopyActionPerformed
        SwingUtil.systemClipboardCopy(this.txtOct.getText());
    }//GEN-LAST:event_btnOctCopyActionPerformed

    private void btnDecCopyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnDecCopyActionPerformed
        SwingUtil.systemClipboardCopy(this.txtDec.getText());
    }//GEN-LAST:event_btnDecCopyActionPerformed

    private void btnHexCopyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHexCopyActionPerformed
        SwingUtil.systemClipboardCopy(this.txtHex.getText());
    }//GEN-LAST:event_btnHexCopyActionPerformed

    private void txtBinActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_txtBinActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_txtBinActionPerformed

    private void rdoByteHex2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rdoByteHex2ActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_rdoByteHex2ActionPerformed

    private void rdoBase16ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rdoBase16ActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_rdoBase16ActionPerformed

    private void btnMurmurHash32ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnMurmurHash32ActionPerformed
        try {
            String inputText = Long.toString(TransUtil.toMurmurHash32(getInputText(), this.getSelectEncode()));
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException e1) {
            this.setOutputText(Util.getStackTraceMessage(e1));
            logger.log(Level.SEVERE, null, e1);
        }
    }//GEN-LAST:event_btnMurmurHash32ActionPerformed

    private void btnMurmurHash64ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnMurmurHash64ActionPerformed
        try {
            String inputText = Long.toString(TransUtil.toMurmurHash64(getInputText(), this.getSelectEncode()));
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException e1) {
            this.setOutputText(Util.getStackTraceMessage(e1));
            logger.log(Level.SEVERE, null, e1);
        }
    }//GEN-LAST:event_btnMurmurHash64ActionPerformed

    private void txtRadix32KeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_txtRadix32KeyReleased
        BigInteger value = RDX32_DOC.getValue();
        this.txtBin.setText(value.toString(2));
        this.txtOct.setText(value.toString(8));
        this.txtDec.setText(value.toString(10));
        this.txtHex.setText(value.toString(16));
    }//GEN-LAST:event_txtRadix32KeyReleased

    private void btnRadix32CopyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRadix32CopyActionPerformed
        SwingUtil.systemClipboardCopy(this.txtRadix32.getText());
    }//GEN-LAST:event_btnRadix32CopyActionPerformed

    private void txtHexActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_txtHexActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_txtHexActionPerformed

    private final java.awt.event.ActionListener historyActionPerformed = new java.awt.event.ActionListener() {
        public void actionPerformed(java.awt.event.ActionEvent evt) {
            JTransCoderProperty property = (JTransCoderProperty) cmbHistory.getSelectedItem();
            if (property != null) {
                clearText();
                setInputText(property.getCurrentInput());
            }
        }
    };

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btnAdler32;
    private javax.swing.JButton btnAnalyze;
    private javax.swing.JButton btnBinCopy;
    private javax.swing.JButton btnCRC32;
    private javax.swing.JButton btnCalc;
    private javax.swing.JButton btnClear;
    private javax.swing.ButtonGroup btnConvertCase;
    private javax.swing.JButton btnDecCopy;
    private javax.swing.JButton btnDecode;
    private javax.swing.JButton btnEncode;
    private javax.swing.JButton btnExport;
    private javax.swing.JButton btnGenerate;
    private javax.swing.ButtonGroup btnGrpEncodeType;
    private javax.swing.ButtonGroup btnGrpNewLine;
    private javax.swing.JButton btnHashMd2;
    private javax.swing.JButton btnHashMd5;
    private javax.swing.JButton btnHashSha1;
    private javax.swing.JButton btnHashSha256;
    private javax.swing.JButton btnHashSha384;
    private javax.swing.JButton btnHashSha512;
    private javax.swing.JButton btnHexCopy;
    private javax.swing.JButton btnImport;
    private javax.swing.JButton btnInputfile;
    private javax.swing.JButton btnMurmurHash32;
    private javax.swing.JButton btnMurmurHash64;
    private javax.swing.JButton btnOctCopy;
    private javax.swing.JPanel btnOutput;
    private javax.swing.JButton btnOutputCopy;
    private javax.swing.JButton btnOutputToInput;
    private javax.swing.JButton btnOutputfile;
    private javax.swing.JButton btnRadix32Copy;
    private javax.swing.JButton btnSavetoFile;
    private javax.swing.JButton btnSmartDecode;
    private javax.swing.JButton btnSmartFormat;
    private javax.swing.JButton btnSmartMatch;
    private javax.swing.JToggleButton btnStoreTypeJKS;
    private javax.swing.JToggleButton btnStoreTypePKCS12;
    private javax.swing.JCheckBox chk64Newline;
    private javax.swing.JCheckBox chk76Newline;
    private javax.swing.JCheckBox chkCharacterCustom;
    private javax.swing.JCheckBox chkCharacterLowerCase;
    private javax.swing.JCheckBox chkCharacterNumber;
    private javax.swing.JCheckBox chkCharacterSpace;
    private javax.swing.JCheckBox chkCharacterUnderline;
    private javax.swing.JCheckBox chkCharacterUpperCase;
    private javax.swing.JCheckBox chkGuess;
    private javax.swing.JCheckBox chkNPadding;
    private javax.swing.JCheckBox chkPadding;
    private javax.swing.JCheckBox chkRawMode;
    private javax.swing.JCheckBox chkViewLineWrap;
    private javax.swing.JCheckBox chkWithByte;
    private javax.swing.JComboBox<String> cmbDateUnit;
    private javax.swing.JComboBox<String> cmbEncoding;
    private javax.swing.JComboBox<String> cmbHistory;
    private javax.swing.JComboBox cmbIILUTF8;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JLabel lblBin;
    private javax.swing.JLabel lblDateEnd;
    private javax.swing.JLabel lblDateFormat;
    private javax.swing.JLabel lblDateStart;
    private javax.swing.JLabel lblDateStep;
    private javax.swing.JLabel lblDec;
    private javax.swing.JLabel lblHex;
    private javax.swing.JLabel lblNumEnd;
    private javax.swing.JLabel lblNumFormat;
    private javax.swing.JLabel lblNumStart;
    private javax.swing.JLabel lblNumStep;
    private javax.swing.JLabel lblOct;
    private javax.swing.JLabel lblPassword;
    private javax.swing.JLabel lblPositionStatus;
    private javax.swing.JLabel lblRadix32;
    private javax.swing.JLabel lblmaximum;
    private javax.swing.JPanel pnlBase64;
    private javax.swing.JPanel pnlBase64URLSafe;
    private javax.swing.JPanel pnlBaseN;
    private javax.swing.JPanel pnlCertificate;
    private javax.swing.JPanel pnlCharacter;
    private javax.swing.JPanel pnlCompress;
    private javax.swing.JPanel pnlConvert;
    private javax.swing.JPanel pnlConvertCase;
    private javax.swing.JPanel pnlCount;
    private javax.swing.JPanel pnlCustom;
    private javax.swing.JPanel pnlDate;
    private javax.swing.JPanel pnlDateEnd;
    private javax.swing.JPanel pnlDateStart;
    private javax.swing.JPanel pnlEncDec;
    private javax.swing.JPanel pnlEncode;
    private javax.swing.JPanel pnlEncodeDecode;
    private javax.swing.JPanel pnlEncoding;
    private javax.swing.JPanel pnlFormat;
    private javax.swing.JPanel pnlGenerate;
    private javax.swing.JPanel pnlHashTrans;
    private javax.swing.JPanel pnlHeader;
    private javax.swing.JPanel pnlHtmlEnc;
    private javax.swing.JPanel pnlHtmlHex;
    private javax.swing.JPanel pnlILLUTF8;
    private javax.swing.JPanel pnlInput;
    private javax.swing.JPanel pnlInputOutput;
    private javax.swing.JPanel pnlInputRaw;
    private javax.swing.JPanel pnlJSHexEnc;
    private javax.swing.JPanel pnlLang;
    private javax.swing.JPanel pnlMail;
    private javax.swing.JPanel pnlNewLine;
    private javax.swing.JPanel pnlNumbers;
    private javax.swing.JPanel pnlOutputRaw;
    private javax.swing.JPanel pnlOutputToInput;
    private javax.swing.JPanel pnlRegex;
    private javax.swing.JPanel pnlRight;
    private javax.swing.JPanel pnlSelect;
    private javax.swing.JPanel pnlSelectOption;
    private javax.swing.JPanel pnlStatus;
    private javax.swing.JPanel pnlStringLength;
    private javax.swing.JPanel pnlTop;
    private javax.swing.JPanel pnlTransButton;
    private javax.swing.JPanel pnlTranslator;
    private javax.swing.JPanel pnlUrl;
    private javax.swing.JPanel pnlWrap;
    private javax.swing.JRadioButton rdoAll;
    private javax.swing.JRadioButton rdoAlphaNum;
    private javax.swing.JRadioButton rdoBase16;
    private javax.swing.JRadioButton rdoBase32;
    private javax.swing.JRadioButton rdoBase64;
    private javax.swing.JRadioButton rdoBase64URLSafe;
    private javax.swing.JRadioButton rdoBeautifyFormat;
    private javax.swing.JRadioButton rdoByteHex;
    private javax.swing.JRadioButton rdoByteHex2;
    private javax.swing.JRadioButton rdoByteOct;
    private javax.swing.JRadioButton rdoCLang;
    private javax.swing.JRadioButton rdoCR;
    private javax.swing.JRadioButton rdoCRLF;
    private javax.swing.ButtonGroup rdoCetificateGrp;
    private javax.swing.JRadioButton rdoConvertPEM;
    private javax.swing.JRadioButton rdoCount1;
    private javax.swing.JRadioButton rdoCount10;
    private javax.swing.JRadioButton rdoCount50;
    private javax.swing.JRadioButton rdoCountNum;
    private javax.swing.ButtonGroup rdoEncodeDecodeGrp;
    private javax.swing.ButtonGroup rdoFormatGrp;
    private javax.swing.JRadioButton rdoGzip;
    private javax.swing.JRadioButton rdoHtml;
    private javax.swing.JRadioButton rdoHtmlByteHex;
    private javax.swing.JRadioButton rdoHtmlDec;
    private javax.swing.JRadioButton rdoHtmlHex;
    private javax.swing.JRadioButton rdoILLUTF8;
    private javax.swing.JRadioButton rdoLF;
    private javax.swing.JRadioButton rdoLength16;
    private javax.swing.JRadioButton rdoLength4;
    private javax.swing.JRadioButton rdoLength8;
    private javax.swing.JRadioButton rdoLengthNum;
    private javax.swing.JRadioButton rdoLigth;
    private javax.swing.JRadioButton rdoLowerCase;
    private javax.swing.JRadioButton rdoMinifyFormat;
    private javax.swing.JRadioButton rdoNone;
    private javax.swing.JRadioButton rdoPunycode;
    private javax.swing.JRadioButton rdoQuotedPrintable;
    private javax.swing.ButtonGroup rdoRandomCountGrp;
    private javax.swing.ButtonGroup rdoRandomLengthGrp;
    private javax.swing.JRadioButton rdoRegex;
    private javax.swing.JRadioButton rdoSQLLang;
    private javax.swing.JRadioButton rdoStandard;
    private javax.swing.JRadioButton rdoUTF7;
    private javax.swing.JRadioButton rdoUnicodeHex;
    private javax.swing.JRadioButton rdoUpperCase;
    private javax.swing.JRadioButton rdoUrl;
    private javax.swing.JRadioButton rdoUrlUnicode;
    private javax.swing.JRadioButton rdoZLIB;
    private javax.swing.JScrollPane scrollGenerate;
    private javax.swing.JScrollPane scrollStatus;
    private javax.swing.JSplitPane splitConvert;
    private javax.swing.JSplitPane splitGenerator;
    private javax.swing.JSpinner spnCountNum;
    private javax.swing.JSpinner spnDateStep;
    private javax.swing.JSpinner spnLengthNum;
    private javax.swing.JSpinner spnNumEnd;
    private javax.swing.JSpinner spnNumStart;
    private javax.swing.JSpinner spnNumStep;
    private javax.swing.JPanel tabBaseBaseConverter;
    private javax.swing.JPanel tabGenerator;
    private javax.swing.JPanel tabRandom;
    private javax.swing.JPanel tabSequence;
    private javax.swing.JPanel tabTokenStrength;
    private javax.swing.JPanel tabTransrator;
    private javax.swing.JTabbedPane tabbetGenerate;
    private javax.swing.JTabbedPane tabbetInput;
    private javax.swing.JTabbedPane tabbetOutput;
    private javax.swing.JTabbedPane tabbetSequence;
    private javax.swing.JTabbedPane tabbetTranscoder;
    private javax.swing.JTextField txtBase;
    private javax.swing.JTextField txtBin;
    private javax.swing.JTextField txtCustom;
    private javax.swing.JTextField txtDateFormat;
    private javax.swing.JTextField txtDec;
    private javax.swing.JTextField txtExponent;
    private javax.swing.JTextArea txtGenarate;
    private javax.swing.JTextField txtHex;
    private javax.swing.JButton txtListCopy;
    private javax.swing.JTextField txtNumFormat;
    private javax.swing.JTextField txtOct;
    private javax.swing.JTextField txtRadix32;
    private javax.swing.JTextArea txtStatus;
    private javax.swing.JTextField txtStoreFile;
    private javax.swing.JTextField txtStorePassword;
    private javax.swing.JTextField txtStrength;
    private javax.swing.JTextArea txtTokenList;
    // End of variables declaration//GEN-END:variables

    public double calcStlength(int base, int exponent) {
        return Math.log(Math.pow(base, exponent)) / Math.log(2.0);
    }

    public void caretUpdate(javax.swing.JTextArea textArea) {
        try {
            String caretstr = getCaretString(textArea);
            List<Integer> encodeCodeList = new ArrayList<>();
            //encodeCodeList.add((int)getCaretChar());
            encodeCodeList.add(getCaretCodePoint(textArea));
            for (int i = 0; i < this.cmbEncoding.getItemCount(); i++) {
                String encode = this.cmbEncoding.getItemAt(i);
                int caretint1 = TransUtil.getCharCode(caretstr, encode);
                encodeCodeList.add((int) caretint1);
            }

            String sttmsg = STATUS_TEXT_FORMAT.format(new Object[]{
                this.txtInputRaw.getText().length(), this.txtInputRaw.getCaret().getDot(), this.txtInputRaw.getSelectionEnd() - this.txtInputRaw.getSelectionStart()});
            this.lblPositionStatus.setText(sttmsg);

            /*
             * ステータス文字コード書式
             */
            StringBuilder statusFormat = new StringBuilder();
            Object[] formatArgsList = new Object[encodeCodeList.size() * 2];
            for (int i = 0; i < formatArgsList.length; i += 2) {
                formatArgsList[i + 0] = ConvertUtil.toHexString(encodeCodeList.get((int) i / 2));
                formatArgsList[i + 1] = encodeCodeList.get((int) i / 2);
                if (i == 0) {
                    statusFormat.append(String.format("%s:\n 0x{%d}({%d,number,#####})", "CharCode", 0, 1));
                } else {
                    String encode = this.cmbEncoding.getItemAt(((int) i / 2) - 1);
                    statusFormat.append(String.format("%s:\n 0x{%d}({%d,number,#####})", encode, i + 0, i + 1));
                }
                statusFormat.append("\n");
            }
            /*
             * ステータス文字コード書式
             */
            MessageFormat statusEncodeFormat = new MessageFormat(statusFormat.toString());
            sttmsg = statusEncodeFormat.format(formatArgsList);
            this.txtStatus.setText(sttmsg);

        } catch (UnsupportedEncodingException e1) {
            logger.log(Level.SEVERE, null, e1);
        }
    }

    public void setEncodingList(List<String> encodingList, String enc) {
        this.cmbEncoding.removeAllItems();
        for (String item : encodingList) {
            this.cmbEncoding.addItem(item);
        }
        this.cmbEncoding.setSelectedItem(enc);
    }

    private void toSmartDecode(String inputText) {
        this.toSmartDecode(inputText, TransUtil.getSmartDecode(inputText));
    }

    private void toSmartDecode(String inputText, TransUtil.EncodePattern encodePattern) {
        String applyCharset = null;
        try {
            if (!this.chkGuess.isSelected() && this.getSelectEncode() != null) {
                applyCharset = this.getSelectEncode();
            }
            String decode = TransUtil.toSmartDecode(inputText, encodePattern, applyCharset);
            this.setOutput(decode, applyCharset);
        } catch (java.lang.NumberFormatException ex) {
            this.setOutputText(Util.getStackTraceMessage(ex));
            logger.log(Level.INFO, null, ex);
        }
    }

    private void clearText() {
        this.setInputText("");
        this.setInputByte(new byte[0]);
        this.setOutputText("");
        this.setOutputByte(new byte[0]);
        this.setOutputFormat("", false);
        this.tabbetInput.setSelectedIndex(this.tabbetInput.indexOfTab("Raw"));
        this.tabbetOutput.remove(this.pnlOutputFormat);
        this.tabbetOutput.setSelectedIndex(this.tabbetOutput.indexOfTab("Raw"));
    }

    private String getInputText() {
        String selectText = "";
        if (this.txtInputRaw.getSelectionStart() == this.txtInputRaw.getSelectionEnd()) {
            selectText = this.txtInputRaw.getText();
        } else {
            selectText = this.txtInputRaw.getSelectedText();
        }
        if (this.chkRawMode.isSelected()) {
            return selectText;
        } else {
            return TransUtil.replaceNewLine(getSelectNewLine(), selectText);
        }
    }

    private void setInputText(String inputText) {
        this.txtInputRaw.setText(inputText);
    }

    private byte[] inputByte = new byte[0];

    private void setInputByte(byte[] inputByte) {
        this.hexInputViewTab.setData(inputByte);
        this.inputByte = inputByte;
    }

    private byte[] getInputByte() {
        return this.inputByte;
    }

    private String getOutputText() {
        return this.txtOutputRaw.getText();
    }

    private void setOutput(String outputText) {
        this.setOutput(outputText, StandardCharsets.ISO_8859_1.name());
    }

    @SuppressWarnings("unchecked")
    private void setOutput(String outputText, String encoding) {
        this.setOutputText(outputText);
        if (encoding == null) {
            encoding = StandardCharsets.ISO_8859_1.name();
        }
        this.setOutputByte(Util.encodeMessage(outputText, encoding));
        if (this.rdoBeautifyFormat.isSelected()) {
            this.setOutputFormat(outputText, true);
        } else {
            this.setOutputFormat(outputText, false);
        }
        this.tabbetOutput.setSelectedIndex(this.tabbetInput.indexOfTab("Raw"));
        this.cmbHistory.removeActionListener(this.historyActionPerformed);
//        this.cmbHistory.removeItemListener(this.historyItemStateChanged);
        MutableComboBoxModel modelHistory = (MutableComboBoxModel) this.cmbHistory.getModel();
        JTransCoderProperty current = this.getProperty();
        for (int i = modelHistory.getSize() - 1; i >= 0; i--) {
            JTransCoderProperty prop = (JTransCoderProperty) modelHistory.getElementAt(i);
            if (current.getCurrentInput().equals(prop.getCurrentInput())) {
                modelHistory.removeElementAt(i);
                break;
            }
        }
        modelHistory.insertElementAt(current, 0);
        modelHistory.setSelectedItem(current);
        this.cmbHistory.addActionListener(this.historyActionPerformed);
    }

    private void setOutputText(String outputText) {
        this.txtOutputRaw.setText(outputText);
        this.txtOutputRaw.setCaretPosition(0);
    }

    private byte[] outputByte = new byte[0];

    private byte[] getOutputByte() {
        return this.outputByte;
    }

    private void setOutputByte(byte[] outputByte) {
        this.hexOutputViewTab.setData(outputByte);
        this.outputByte = outputByte;
    }

    private void setOutputFormat(String outputText, boolean pretty) {
        try {
            this.txtOutputFormat.setText("");
            this.tabbetOutput.remove(this.pnlOutputFormat);
            if (FormatUtil.isJson(outputText)) {
                this.txtOutputFormat.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JSON);
                this.tabbetOutput.addTab("JSON", this.pnlOutputFormat);
                this.txtOutputFormat.setText(FormatUtil.prettyJson(outputText, pretty));
            } else if (FormatUtil.isXml(outputText)) {
                this.txtOutputFormat.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_XML);
                this.tabbetOutput.addTab("XML", this.pnlOutputFormat);
                this.txtOutputFormat.setText(FormatUtil.prettyXml(outputText, pretty));
            }
            this.txtOutputFormat.setCaretPosition(0);
        } catch (IOException ex) {
            logger.log(Level.SEVERE, null, ex);
        }
    }

    void sendToJTransCoder(String text) {
        this.setInputText(text);
        this.setInputByte(Util.getRawByte(text));
    }

    byte[] receiveFromJTransCoder() {
        return this.getOutputByte();
    }

    private String getSelectEncode() {
        String enc = StandardCharsets.ISO_8859_1.name();
        if (this.chkRawMode.isSelected()) {
            enc = StandardCharsets.ISO_8859_1.name();
        } else {
            int index = this.cmbEncoding.getSelectedIndex();
            if (index > -1) {
                enc = this.cmbEncoding.getModel().getElementAt(index);
            }
        }
        return enc;
    }

    private EncodeType getEncodeType() {
        if (this.rdoAll.isSelected()) {
            return EncodeType.ALL;
        } else if (this.rdoAlphaNum.isSelected()) {
            return EncodeType.ALPHANUM;
        } else if (this.rdoLigth.isSelected()) {
            return EncodeType.LIGHT;
        } else if (this.rdoStandard.isSelected()) {
            return EncodeType.STANDARD;
        }
        return EncodeType.ALL;
    }

    private void setEncodeType(EncodeType type) {
        switch (type) {
            case ALL:
                this.rdoAll.setSelected(true);
                break;
            case ALPHANUM:
                this.rdoAlphaNum.setSelected(true);
                break;
            case LIGHT:
                this.rdoLigth.setSelected(true);
                break;
            case STANDARD:
                this.rdoStandard.setSelected(true);
                break;
        }
    }

    private NewLine getSelectNewLine() {
        NewLine newLineMode = NewLine.CRLF;
        if (this.rdoNone.isSelected()) {
            newLineMode = NewLine.NONE;
        } else if (this.rdoCRLF.isSelected()) {
            newLineMode = NewLine.CRLF;
        } else if (this.rdoLF.isSelected()) {
            newLineMode = NewLine.LF;
        } else if (this.rdoCR.isSelected()) {
            newLineMode = NewLine.CR;
        }
        return newLineMode;
    }

    private void setNewLine(NewLine newLineMode) {
        switch (newLineMode) {
            case NONE:
                this.rdoNone.setSelected(true);
                break;
            case CRLF:
                this.rdoCRLF.setSelected(true);
                break;
            case CR:
                this.rdoCR.setSelected(true);
                break;
            case LF:
                this.rdoLF.setSelected(true);
                break;
        }
    }

    private ConvertCase getConvertCase() {
        if (this.rdoUpperCase.isSelected()) {
            return ConvertCase.UPPER;
        } else if (this.rdoLowerCase.isSelected()) {
            return ConvertCase.LOWLER;
        }
        return ConvertCase.LOWLER;
    }

    private void setConvertCase(ConvertCase convertCase) {
        switch (convertCase) {
            case UPPER:
                this.rdoUpperCase.setSelected(true);
                break;
            case LOWLER:
                this.rdoLowerCase.setSelected(true);
                break;
        }
    }

    private int getCharacterLength() {
        int len = -1;
        if (this.rdoLength4.isSelected()) {
            len = 4;
        } else if (this.rdoLength8.isSelected()) {
            len = 8;
        } else if (this.rdoLength16.isSelected()) {
            len = 16;
        } else if (this.rdoLengthNum.isSelected()) {
            len = (Integer) this.spnLengthNum.getModel().getValue();
        }
        return len;
    }

    private int getGenerateCount() {
        int cnt = -1;
        if (this.rdoCount1.isSelected()) {
            cnt = 1;
        } else if (this.rdoCount10.isSelected()) {
            cnt = 10;
        } else if (this.rdoCount50.isSelected()) {
            cnt = 50;
        } else if (this.rdoCountNum.isSelected()) {
            cnt = (Integer) this.spnCountNum.getModel().getValue();
        }
        return cnt;
    }

    private String getRangeChars() {
        StringBuilder buff = new StringBuilder();
        if (this.chkCharacterNumber.isSelected()) {
            buff.append("1234567890");
        }
        if (this.chkCharacterLowerCase.isSelected()) {
            buff.append("abcdefghijklmnopqrstuvwxyz");
        }
        if (this.chkCharacterUpperCase.isSelected()) {
            buff.append("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        }
        if (this.chkCharacterUnderline.isSelected()) {
            buff.append("_");
        }
        if (this.chkCharacterSpace.isSelected()) {
            buff.append(" ");
        }
        if (this.chkCharacterCustom.isSelected()) {
            buff.append(this.txtCustom.getText());
        }
        return buff.toString();
    }

    public JTransCoderProperty getProperty() {
        final JTransCoderProperty transcoderProp = new JTransCoderProperty();
        transcoderProp.setEncodeType(this.getEncodeType());
        transcoderProp.setConvertCase(this.getConvertCase());
        transcoderProp.setNewLine(this.getSelectNewLine());
        transcoderProp.setLineWrap(this.chkViewLineWrap.isSelected());
        transcoderProp.setRawEncoding(this.chkRawMode.isSelected());
        transcoderProp.setGuessEncoding(this.chkGuess.isSelected());
        transcoderProp.setSelectEncoding((String) this.cmbEncoding.getSelectedItem());
        transcoderProp.setCurrentInput(this.getInputText());
        return transcoderProp;
    }

    public void setProperty(JTransCoderProperty transcoderProp) {
        this.setEncodeType(transcoderProp.getEncodeType());
        this.setConvertCase(transcoderProp.getConvertCase());
        this.setNewLine(transcoderProp.getNewLine());
        this.chkViewLineWrap.setSelected(transcoderProp.isLineWrap());
        this.chkViewLineWrapActionPerformed(null);
        this.chkRawMode.setSelected(transcoderProp.isRawEncoding());
        this.chkGuess.setSelected(transcoderProp.isGuessEncoding());
        this.cmbEncoding.setSelectedItem(transcoderProp.getSelectEncoding());
        this.setInputText(transcoderProp.getCurrentInput());
        chkRawModeActionPerformed(null);
        chkGuessActionPerformed(null);
        chkViewLineWrapActionPerformed(null);
    }

}
