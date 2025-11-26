package yagura.view;

import burp.api.montoya.extension.ExtensionUnloadingHandler;
import extension.helpers.BouncyUtil;
import extend.util.external.CodecUtil;
import extend.util.external.TransUtil;
import java.awt.BorderLayout;
import java.awt.Component;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.IllegalFormatException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import java.time.LocalDate;
import javax.swing.MutableComboBoxModel;
import java.io.BufferedOutputStream;
import java.math.BigInteger;
import java.util.HashSet;
import java.util.concurrent.ExecutionException;
import javax.swing.SwingWorker;
import extend.util.external.FormatUtil;
import extend.util.external.ThemeUI;
import extend.util.external.TransUtil.ConvertCase;
import extend.util.external.TransUtil.DateUnit;
import extend.util.external.TransUtil.EncodeType;
import extend.util.external.TransUtil.NewLine;
import extension.burp.BurpUtil;
import extension.helpers.ConvertUtil;
import extension.helpers.FileUtil;
import extension.helpers.HashUtil;
import extension.helpers.HttpUtil;
import extension.helpers.IpUtil;
import extension.helpers.MatchUtil;
import extension.helpers.StringUtil;
import extension.helpers.SwingUtil;
import extension.view.base.CustomTableModel;
import extension.view.layout.VerticalFlowLayout;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.math.BigDecimal;
import java.text.ParseException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Calendar;
import java.util.Date;
import javax.swing.JSpinner;
import javax.swing.JTextField;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import yagura.model.JTransCoderProperty;
import yagura.model.UniversalViewProperty;
import extension.burp.IBurpTab;
import extension.helpers.DateUtil;
import extension.helpers.SmartCodec;
import extension.helpers.jws.JWKToken;
import java.io.StringWriter;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import javax.swing.AbstractButton;
import javax.swing.ButtonModel;
import javax.swing.DefaultComboBoxModel;
import org.apache.commons.codec.DecoderException;
import extension.helpers.jws.JWSToken;

/**
 *
 * @author isayan
 */
public class JTransCoderTab extends javax.swing.JPanel implements IBurpTab, ExtensionUnloadingHandler {

    private final static Logger logger = Logger.getLogger(JTransCoderTab.class.getName());

    private final static java.util.ResourceBundle BUNDLE = java.util.ResourceBundle.getBundle("yagura/resources/Resource");

    final PropertyChangeListener propertyListener = new PropertyChangeListener() {
        @Override
        public void propertyChange(PropertyChangeEvent evt) {
            ThemeUI.applyStyleTheme(txtOutputRaw);
            ThemeUI.applyStyleTheme(txtOutputFormat);
        }
    };

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

    private javax.swing.JScrollPane scrollInputRaw;
    private javax.swing.JTextArea txtInputRaw;

    //private javax.swing.JScrollPane scrollOutputRaw;
    //private javax.swing.JTextArea txtOutputRaw;
    //private javax.swing.JScrollPane scrollOutputFormat;
    //private javax.swing.JTextArea txtOutputFormat;
    private org.fife.ui.rtextarea.RTextScrollPane scrollOutputRaw;
    private org.fife.ui.rsyntaxtextarea.RSyntaxTextArea txtOutputRaw;

    private org.fife.ui.rtextarea.RTextScrollPane scrollOutputFormat;
    private org.fife.ui.rsyntaxtextarea.RSyntaxTextArea txtOutputFormat;

    private final static DateTimeFormatter SYSTEM_ZONE_DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss zzz");

    private final static String[] SHORT_ZONEIDS = {
        "GMT", "ACT", "AET", "AGT", "ART", "AST", "BET", "BST", "CAT", "CNT", "CST", "CTT", "EAT", "ECT", "IET", "IST", "JST", "MIT", "NET", "NST", "PLT", "PNT", "PRT", "PST", "SST", "VST", "EST", "MST", "HST"
    };

    private final ViewStateDecoderTab viewStateDecoderTab = new ViewStateDecoderTab();

    private final JWSDecoderTab jwsDecoderTab = new JWSDecoderTab();
    private final JWSEncoderTab jwsEncoderTab = new JWSEncoderTab();

    private final JWKTab jwkTab = new JWKTab();

    final FocusListener FIRE_FOCUS = new FocusListener() {
        @Override
        public void focusGained(FocusEvent e) {
        }

        @Override
        public void focusLost(FocusEvent e) {
            updateZoneDateTime();
        }
    };

    private void updateZoneDateTime() {
        ZonedDateTime cdtm = getConverterZoneDateTime();
        long java_value = cdtm.toInstant().toEpochMilli();
        long unix_value = java_value / 1000L;

        this.txtUnixtime.setValue(unix_value);
        this.txtJavaSerial.setValue(java_value);
        BigDecimal excel_serial = TransUtil.toExcelSerial(unix_value);
        this.txtExcelSerial.setValue(excel_serial.doubleValue());

        this.setSystemZoneDate(cdtm);
    }

    private final CertificateTab certificateTab = new CertificateTab();

    private File currentPrivateKeyDirectory = null;

    private final DefaultComboBoxModel modelAlgo = new DefaultComboBoxModel();

   // https://docs.oracle.com/javase/jp/11/docs/specs/security/standard-names.html#keypairgenerator-algorithms
    private final static String[] ALGORITHM = new String[]{"RSA", "DSA", "EC", "Ed25519", "Ed448"};
    private final static Map<String, Boolean> KEY_USE_MAP = new HashMap();
    private final static int[] RSA_KEYSIZE = new int[]{512, 1024, 2048, 3072, 4098};
    private final static int[] DSA_KEYSIZE = new int[]{512, 768, 1024, 2048, 3072};
    private final static int[] EC_KEYSIZE = new int[]{224, 256, 384, 521};
    private final static int[] ED25519_KEYSIZE = new int[]{255};
    private final static int[] ED448_KEYSIZE = new int[]{448};

    static {
        KEY_USE_MAP.put("RSA", Boolean.TRUE);
        KEY_USE_MAP.put("DSA", Boolean.TRUE);
        KEY_USE_MAP.put("EC", Boolean.TRUE);
        KEY_USE_MAP.put("Ed25519", Boolean.FALSE);
        KEY_USE_MAP.put("Ed448", Boolean.FALSE);
    }

    private void customizeComponents() {

        /**
         * * UI design start **
         */
        if (BurpUtil.isLoadClass("org.bouncycastle.jce.provider.BouncyCastleProvider")) {
            this.tabbetTranscoder.addTab(certificateTab.getTabCaption(), certificateTab);
        }

        this.tabbetTranscoder.addTab(this.viewStateDecoderTab.getTabCaption(), this.viewStateDecoderTab);
        this.tabbetTranscoder.addTab(this.jwsDecoderTab.getTabCaption(), this.jwsDecoderTab);
        this.tabbetTranscoder.addTab(this.jwsEncoderTab.getTabCaption(), this.jwsEncoderTab);
        this.tabbetTranscoder.addTab(this.jwkTab.getTabCaption(), this.jwkTab);

//        this.txtInputRaw = new org.fife.ui.rsyntaxtextarea.RSyntaxTextArea();
        this.txtInputRaw = new javax.swing.JTextArea();
        this.txtInputRaw.setLineWrap(true);
        this.txtInputRaw.setWrapStyleWord(false);
        this.txtInputRaw.setEditable(true);
//        this.txtInputRaw.setCodeFoldingEnabled(false);
//        this.txtInputRaw.setHyperlinksEnabled(false);
//        this.txtInputRaw.setHighlightCurrentLine(false);
//        this.txtInputRaw.setHyperlinksEnabled(false);
//        this.txtInputRaw.setBackground(SystemColor.text);

        // Drag and Drop
        this.txtInputRaw.setTransferHandler(new SwingUtil.FileDropAndClipbordTransferHandler() {
            @Override
            public void setData(File file, byte[] rawData) {
                setInputText(StringUtil.getBytesRawString(rawData));
            }
        });

//        this.scrollInputRaw = new org.fife.ui.rtextarea.RTextScrollPane(this.txtInputRaw);
        this.scrollInputRaw = new javax.swing.JScrollPane();
        this.scrollInputRaw.setViewportView(this.txtInputRaw);

//        this.tabbetInput.addTab("Raw", this.scrollInputRaw);
        this.pnlInputRaw.add(this.scrollInputRaw, BorderLayout.CENTER);

//        scrollURaw.setViewportView(txtURaw);
//        this.pnlInputRaw.add(this.scrollInputRaw, BorderLayout.CENTER);
        this.txtOutputRaw = new org.fife.ui.rsyntaxtextarea.RSyntaxTextArea();
//        this.txtOutputRaw = new javax.swing.JTextArea();

//        this.txtOutputRaw.setFont(new Font("ＭＳ ゴシック", Font.PLAIN, 24));
        this.txtOutputRaw.setEditable(false);
        this.txtOutputRaw.setHyperlinksEnabled(false);
        this.txtOutputRaw.setHighlightCurrentLine(false);
        this.txtOutputRaw.setHyperlinksEnabled(false);
//        this.txtOutputRaw.setBackground(SystemColor.text);
        this.scrollOutputRaw = new org.fife.ui.rtextarea.RTextScrollPane(this.txtOutputRaw);
//        this.scrollOutputRaw = new javax.swing.JScrollPane(this.txtOutputRaw);
        this.pnlOutputRaw.add(this.scrollOutputRaw, BorderLayout.CENTER);

        this.txtOutputFormat = new org.fife.ui.rsyntaxtextarea.RSyntaxTextArea();
//        this.txtOutputFormat = new javax.swing.JTextArea();

        this.txtOutputFormat.setEditable(false);
        this.txtOutputFormat.setCodeFoldingEnabled(true);
        this.txtOutputFormat.setHyperlinksEnabled(false);
        this.txtOutputFormat.setHighlightCurrentLine(false);
//        this.txtOutputFormat.setBackground(SystemColor.text);
//        this.txtOutputFormat.setCurrentLineHighlightColor(SystemColor.textHighlight);

//        this.scrollOutputFormat = new javax.swing.JScrollPane(this.txtOutputFormat);
        this.scrollOutputFormat = new org.fife.ui.rtextarea.RTextScrollPane(this.txtOutputFormat);

        this.pnlTransAction.setLayout(new VerticalFlowLayout());

        this.tabbetOutput.addTab("Hex", this.hexOutputViewTab);
        this.hexOutputViewTab.setEnabled(false);

        this.tabbetInput.addTab("Hex", this.hexInputViewTab);
        this.hexInputViewTab.setEnabled(false);

        this.setEncodingList(UniversalViewProperty.getDefaultEncodingList(), StandardCharsets.UTF_8.name());

        this.cmbEncoding.setEnabled(!this.chkRawMode.isSelected());

        this.pnlHashCheckSum.setLayout(new VerticalFlowLayout());

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

        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.YEAR, 1);
        this.setGeneraterDateEnd(calendar.getTime());

        /**
         * * UI design end **
         */
        int tz_offset = 0;
        ZoneId systemZone = ZoneId.systemDefault();
        for (int i = 0; i < SHORT_ZONEIDS.length; i++) {
            ZoneId zoneId = ZoneId.of(SHORT_ZONEIDS[i], ZoneId.SHORT_IDS);
            String shortIDS = "GMT".equals(SHORT_ZONEIDS[i]) ? "Greenwich Mean Time" : ZoneId.SHORT_IDS.get(SHORT_ZONEIDS[i]);
            this.cmbTimezone.addItem(SHORT_ZONEIDS[i] + " - " + shortIDS + " (" + zoneId.getRules().getOffset(Instant.EPOCH) + ")");
            if (systemZone.equals(zoneId)) {
                tz_offset = i;
            }
        }

        this.cmbTimezone.setSelectedIndex(tz_offset);
        //this.cmbTimezone.setVisible(false);

        this.lblDate.setText(String.format("Date(%s):", ZoneId.systemDefault().getId()));

        this.txtInputRaw.addCaretListener(new javax.swing.event.CaretListener() {
            @Override
            public void caretUpdate(javax.swing.event.CaretEvent evt) {
                txtInputRawCaretUpdate(evt);
            }
        });

        this.txtOutputRaw.addCaretListener(new javax.swing.event.CaretListener() {
            @Override
            public void caretUpdate(javax.swing.event.CaretEvent evt) {
                txtOutputRawCaretUpdate(evt);
            }
        });

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

        this.spnZoneDateTime.addFocusListener(FIRE_FOCUS);
        final JTextField innerDateLimit = ((JSpinner.DefaultEditor) this.spnZoneDateTime.getEditor()).getTextField();
        innerDateLimit.addFocusListener(FIRE_FOCUS);

        this.FIRE_FOCUS.focusLost(null);

        this.doStateDecodeChange();

        this.propertyListener.propertyChange(null);
        ThemeUI.addPropertyChangeListener(this.propertyListener);

        // KeyPairGenerager

        this.cmbAlgorithm.setModel(modelAlgo);
        this.modelAlgo.addAll(List.of(ALGORITHM));
        this.cmbAlgorithm.setSelectedIndex(0);


    }

    private void txtInputRawCaretUpdate(javax.swing.event.CaretEvent evt) {
        this.caretUpdate(this.txtInputRaw);
    }

    private void txtOutputRawCaretUpdate(javax.swing.event.CaretEvent evt) {
        this.caretUpdate(this.txtOutputRaw);
    }

    private ZoneId getSelectZoneId() {
        int index = this.cmbTimezone.getSelectedIndex();
        if (0 <= index && index < SHORT_ZONEIDS.length) {
            return ZoneId.of(SHORT_ZONEIDS[index], ZoneId.SHORT_IDS);
        } else {
            return ZoneId.systemDefault();
        }
    }

    private void setConverterDateTime(Date value) {
        this.spnZoneDateTime.setValue(value);
    }

    private Date getConverterDateTime() {
        Date date = new Date();
        try {
            this.spnZoneDateTime.commitEdit();
            date = (Date) this.spnZoneDateTime.getValue();
        } catch (ParseException ex) {
            logger.log(Level.INFO, ex.getMessage(), ex);
        }
        return date;
    }

    private void setConverterZoneDateTime(long java_serial_time) {
        ZoneId zoneId = getSelectZoneId();
        LocalDateTime ldtm = LocalDateTime.ofInstant(Instant.ofEpochMilli(java_serial_time), zoneId);
        this.spnZoneDateTime.setValue(DateUtil.toZoneWithDate(ldtm, zoneId));
    }

    private ZonedDateTime getConverterZoneDateTime() {
        Date date = this.getConverterDateTime();
        ZoneId zoneId = getSelectZoneId();
        ZonedDateTime zdtm = DateUtil.toZoneWithZoneDate(date, zoneId);
        return zdtm;
    }

    private void setGeneraterDateStart(Date value) {
        this.spnDateStart.setValue(value);
    }

    private Date getGeneraterDateStart() {
        Date date = new Date();
        try {
            this.spnDateStart.commitEdit();
            date = (Date) this.spnDateStart.getValue();
        } catch (ParseException ex) {
            logger.log(Level.INFO, ex.getMessage(), ex);
        }
        return date;
    }

    private void setGeneraterDateEnd(Date value) {
        this.spnDateEnd.setValue(value);
    }

    private Date getGeneraterDateEnd() {
        Date date = new Date();
        try {
            this.spnDateEnd.commitEdit();
            date = (Date) this.spnDateEnd.getValue();
        } catch (ParseException ex) {
            logger.log(Level.INFO, ex.getMessage(), ex);
        }
        return date;
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
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
        btnGrpKeySize = new javax.swing.ButtonGroup();
        btnGrpExportKeyPair = new javax.swing.ButtonGroup();
        tabbetTranscoder = new javax.swing.JTabbedPane();
        tabTransrator = new javax.swing.JPanel();
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
        rdoURLSafe = new javax.swing.JRadioButton();
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
        tabbetTransAction = new javax.swing.JTabbedPane();
        pnlTransAction = new javax.swing.JPanel();
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
        chk76Newline = new javax.swing.JCheckBox();
        chk64Newline = new javax.swing.JCheckBox();
        chkPadding = new javax.swing.JCheckBox();
        pnlBase64URLSafe = new javax.swing.JPanel();
        rdoBase64URLSafe = new javax.swing.JRadioButton();
        rdoBase64andURL = new javax.swing.JRadioButton();
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
        rdoHtmlUnicode = new javax.swing.JRadioButton();
        rdoHtmlByteHex = new javax.swing.JRadioButton();
        pnlJSUnicodeEnc = new javax.swing.JPanel();
        rdoUnicodeHex = new javax.swing.JRadioButton();
        rdoUnicodeHex2 = new javax.swing.JRadioButton();
        pnlJSHexEnc = new javax.swing.JPanel();
        rdoByteNoneHex = new javax.swing.JRadioButton();
        rdoByteXHex = new javax.swing.JRadioButton();
        rdoByteHex2 = new javax.swing.JRadioButton();
        rdoByteOct = new javax.swing.JRadioButton();
        pnlCompress = new javax.swing.JPanel();
        rdoGzip = new javax.swing.JRadioButton();
        rdoZLIB = new javax.swing.JRadioButton();
        rdoZLIB_NOWRAP = new javax.swing.JRadioButton();
        pnlILLUTF8 = new javax.swing.JPanel();
        rdoUTF7 = new javax.swing.JRadioButton();
        rdoILLUTF8 = new javax.swing.JRadioButton();
        cmbIILUTF8 = new javax.swing.JComboBox();
        pnlLang = new javax.swing.JPanel();
        rdoCLang = new javax.swing.JRadioButton();
        rdoJSON = new javax.swing.JRadioButton();
        rdoSQLLang = new javax.swing.JRadioButton();
        rdoRegex = new javax.swing.JRadioButton();
        chkMetaChar = new javax.swing.JCheckBox();
        pnlFormat = new javax.swing.JPanel();
        rdoMinifyFormat = new javax.swing.JRadioButton();
        rdoBeautifyFormat = new javax.swing.JRadioButton();
        btnSmartFormat = new javax.swing.JButton();
        pnlRegex = new javax.swing.JPanel();
        btnSmartMatch = new javax.swing.JButton();
        chkWithByte = new javax.swing.JCheckBox();
        pnlHashCheckSum = new javax.swing.JPanel();
        pnlHashTrans = new javax.swing.JPanel();
        btnHashMd2 = new javax.swing.JButton();
        btnHashMd4 = new javax.swing.JButton();
        btnHashMd5 = new javax.swing.JButton();
        btnHashSha1 = new javax.swing.JButton();
        btnHashSha224 = new javax.swing.JButton();
        btnHashSha256 = new javax.swing.JButton();
        btnHashSha384 = new javax.swing.JButton();
        btnHashSha512 = new javax.swing.JButton();
        btnHashSha512_224 = new javax.swing.JButton();
        btnHashSha512_256 = new javax.swing.JButton();
        btnHashSha3_224 = new javax.swing.JButton();
        btnHashSha3_256 = new javax.swing.JButton();
        btnHashSha3_384 = new javax.swing.JButton();
        btnHashSha3_512 = new javax.swing.JButton();
        btnHashSHAKE128 = new javax.swing.JButton();
        btnHashSHAKE256 = new javax.swing.JButton();
        btnHashSKEIN256_128 = new javax.swing.JButton();
        btnHashSKEIN256_160 = new javax.swing.JButton();
        btnHashSKEIN256_224 = new javax.swing.JButton();
        btnHashSKEIN256_256 = new javax.swing.JButton();
        btnHashSKEIN512_128 = new javax.swing.JButton();
        btnHashSKEIN512_160 = new javax.swing.JButton();
        btnHashSKEIN512_224 = new javax.swing.JButton();
        btnHashSKEIN512_256 = new javax.swing.JButton();
        btnHashSKEIN512_384 = new javax.swing.JButton();
        btnHashSKEIN512_512 = new javax.swing.JButton();
        btnHashSKEIN1024_384 = new javax.swing.JButton();
        btnHashSKEIN1024_512 = new javax.swing.JButton();
        btnHashSKEIN1024_1024 = new javax.swing.JButton();
        btnHashKECCAK224 = new javax.swing.JButton();
        btnHashKECCAK256 = new javax.swing.JButton();
        btnHashKECCAK288 = new javax.swing.JButton();
        btnHashKECCAK384 = new javax.swing.JButton();
        btnHashKECCAK512 = new javax.swing.JButton();
        btnHashHARAKA256 = new javax.swing.JButton();
        btnHashHARAKA512 = new javax.swing.JButton();
        btnHashRIPEMD128 = new javax.swing.JButton();
        btnHashRIPEMD129 = new javax.swing.JButton();
        btnHashRIPEMD256 = new javax.swing.JButton();
        btnHashRIPEMD320 = new javax.swing.JButton();
        btnHashGOST3411 = new javax.swing.JButton();
        btnHashGOST3411_2012_256 = new javax.swing.JButton();
        btnHashGOST3411_2012_512 = new javax.swing.JButton();
        btnHashDSTU7564_256 = new javax.swing.JButton();
        btnHashDSTU7564_384 = new javax.swing.JButton();
        btnHashDSTU7564_512 = new javax.swing.JButton();
        btnHashBLAKE2B_160 = new javax.swing.JButton();
        btnHashBLAKE2B_256 = new javax.swing.JButton();
        btnHashBLAKE2B_384 = new javax.swing.JButton();
        btnHashBLAKE2B_512 = new javax.swing.JButton();
        btnHashBLAKE2S_128 = new javax.swing.JButton();
        btnHashBLAKE2S_160 = new javax.swing.JButton();
        btnHashBLAKE2_S224 = new javax.swing.JButton();
        btnHashBLAKE2S_256 = new javax.swing.JButton();
        btnHashBLAKE3_256 = new javax.swing.JButton();
        btnHashPARALLELHASH128_256 = new javax.swing.JButton();
        btnHashPARALLELHASH256_512 = new javax.swing.JButton();
        btnHashTiger = new javax.swing.JButton();
        btnHashWHIRLPOOL = new javax.swing.JButton();
        btnHashSM3 = new javax.swing.JButton();
        btnHashTUPLEHASH128_256 = new javax.swing.JButton();
        btnHashTUPLEHASH256_512 = new javax.swing.JButton();
        btnHashISAP = new javax.swing.JButton();
        btnHashAscon = new javax.swing.JButton();
        btnHashAsconA = new javax.swing.JButton();
        btnHashAsconXof = new javax.swing.JButton();
        btnHashAsconXofA = new javax.swing.JButton();
        btnHashESCH256 = new javax.swing.JButton();
        btnHashESCH384 = new javax.swing.JButton();
        btnHashPhotonBeetle = new javax.swing.JButton();
        btnHashXoodyak = new javax.swing.JButton();
        pnlCheckSumTrans = new javax.swing.JPanel();
        btnCRC32 = new javax.swing.JButton();
        btnCRC32C = new javax.swing.JButton();
        btnAdler32 = new javax.swing.JButton();
        btnMurmurHash2_32 = new javax.swing.JButton();
        btnMurmurHash2_64 = new javax.swing.JButton();
        btnXXHash32 = new javax.swing.JButton();
        btnMurmurHash3_32x86 = new javax.swing.JButton();
        btnMurmurHash3_128x64 = new javax.swing.JButton();
        tabGenerator = new javax.swing.JPanel();
        splitGenerator = new javax.swing.JSplitPane();
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
        cmbDateUnit = new javax.swing.JComboBox<>();
        spnDateStep = new javax.swing.JSpinner();
        spnDateStart = new javax.swing.JSpinner();
        spnDateEnd = new javax.swing.JSpinner();
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
        pnlGenerateKey = new javax.swing.JPanel();
        pnlKeyPairAlgorithm = new javax.swing.JPanel();
        lbAlgorithm = new javax.swing.JLabel();
        lblKeySize = new javax.swing.JLabel();
        cmbAlgorithm = new javax.swing.JComboBox<>();
        lblKeyPairValid = new javax.swing.JLabel();
        pnlKeySize = new javax.swing.JPanel();
        pnlKeyPairConvertFormat = new javax.swing.JPanel();
        rdoConvertKeyPairPEM = new javax.swing.JRadioButton();
        rdoConvertKeyPairJWK = new javax.swing.JRadioButton();
        pnlRight = new javax.swing.JPanel();
        btnGenerate = new javax.swing.JButton();
        btnGeneCopy = new javax.swing.JButton();
        btnGeneSavetoFile = new javax.swing.JButton();
        btnGeneClear = new javax.swing.JButton();
        pnlBottom = new javax.swing.JPanel();
        scrollGenerate = new javax.swing.JScrollPane();
        txtGenarate = new javax.swing.JTextArea();
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
        tabbetConverter = new javax.swing.JTabbedPane();
        tabDateConverter = new javax.swing.JPanel();
        lblUnixtime = new javax.swing.JLabel();
        btnUnixtimeCopy = new javax.swing.JButton();
        lblJavaSerial = new javax.swing.JLabel();
        btnJavaSerialCopy = new javax.swing.JButton();
        lblExcelSerial = new javax.swing.JLabel();
        btnExcelSerial = new javax.swing.JButton();
        lblZoneDate = new javax.swing.JLabel();
        spnZoneDateTime = new javax.swing.JSpinner();
        cmbTimezone = new javax.swing.JComboBox<>();
        txtExcelSerial = new javax.swing.JFormattedTextField();
        txtJavaSerial = new javax.swing.JFormattedTextField();
        txtUnixtime = new javax.swing.JFormattedTextField();
        lblDate = new javax.swing.JLabel();
        btnZoneDateCopy = new javax.swing.JButton();
        txtSystemZoneDate = new javax.swing.JTextField();
        lblDateGMT = new javax.swing.JLabel();
        txtSystemZoneDateGMT = new javax.swing.JTextField();
        btnZoneDateGMTCopy = new javax.swing.JButton();
        tabBaseConverter = new javax.swing.JPanel();
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
        tabIPFormatConverter = new javax.swing.JPanel();
        lblDotDeclIP = new javax.swing.JLabel();
        pnlDotDecIP = new javax.swing.JPanel();
        txtDec1 = new javax.swing.JTextField();
        txtDec2 = new javax.swing.JTextField();
        txtDec3 = new javax.swing.JTextField();
        txtDec4 = new javax.swing.JTextField();
        btnDecIPPaste = new javax.swing.JButton();
        btnDecIPConvert = new javax.swing.JButton();
        lblDotOctCIP = new javax.swing.JLabel();
        txtDotOctCIP = new javax.swing.JTextField();
        btnDotOctCIP = new javax.swing.JButton();
        btnOctIP = new javax.swing.JButton();
        txtOctIP = new javax.swing.JTextField();
        lblOctIP = new javax.swing.JLabel();
        lblHexIP = new javax.swing.JLabel();
        txtHexIP = new javax.swing.JTextField();
        btnHexIP = new javax.swing.JButton();
        lblDotHexCIP = new javax.swing.JLabel();
        txtDotHexCIP = new javax.swing.JTextField();
        btnDotHexCIP = new javax.swing.JButton();
        lblIntIP = new javax.swing.JLabel();
        txtIntIP = new javax.swing.JTextField();
        btnIntIP = new javax.swing.JButton();
        lblIPValid = new javax.swing.JLabel();
        lblDotHexBIP = new javax.swing.JLabel();
        txtDotHexBIP = new javax.swing.JTextField();
        btnDotHexBIP = new javax.swing.JButton();
        lblDotHexAIP = new javax.swing.JLabel();
        txtDotHexAIP = new javax.swing.JTextField();
        btnDotHexAIP = new javax.swing.JButton();
        lblDotDectBIP = new javax.swing.JLabel();
        txtDotDecBIP = new javax.swing.JTextField();
        btnDotDecBIP = new javax.swing.JButton();
        txtDotDecAIP = new javax.swing.JTextField();
        btnDotDecAIP = new javax.swing.JButton();
        lblIPv4MappedIPv6 = new javax.swing.JLabel();
        txtIPv4MappedIPv6 = new javax.swing.JTextField();
        btnDotAHexIP1 = new javax.swing.JButton();
        lblIPv4toUnicode = new javax.swing.JLabel();
        txtIPv4ToUnicode = new javax.swing.JTextField();
        btnIPv4ToUnicode = new javax.swing.JButton();
        lblDotOcBtIP = new javax.swing.JLabel();
        txtDotOctBIP = new javax.swing.JTextField();
        btnDotBOctIP = new javax.swing.JButton();
        lblDotOctAIP = new javax.swing.JLabel();
        btnDotOctAIP = new javax.swing.JButton();
        txtDotOctAIP = new javax.swing.JTextField();
        lblTailDotDecCIP = new javax.swing.JLabel();
        txtDotTailDecCIP = new javax.swing.JTextField();
        btnDotTailDecCIP = new javax.swing.JButton();
        lblDotDectAIP = new javax.swing.JLabel();

        setLayout(new java.awt.BorderLayout());

        tabTransrator.setLayout(new java.awt.BorderLayout());

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
                .addComponent(btnInputfile, javax.swing.GroupLayout.DEFAULT_SIZE, 142, Short.MAX_VALUE)
                .addContainerGap())
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
                .addComponent(btnOutputfile, javax.swing.GroupLayout.DEFAULT_SIZE, 142, Short.MAX_VALUE)
                .addContainerGap())
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
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, pnlEncodingLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(pnlEncodingLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(cmbEncoding, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addGroup(pnlEncodingLayout.createSequentialGroup()
                        .addGap(0, 0, Short.MAX_VALUE)
                        .addComponent(chkRawMode)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(chkGuess)))
                .addContainerGap())
        );
        pnlEncodingLayout.setVerticalGroup(
            pnlEncodingLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlEncodingLayout.createSequentialGroup()
                .addGroup(pnlEncodingLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(chkRawMode)
                    .addComponent(chkGuess))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(cmbEncoding, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
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
                .addGroup(pnlOutputToInputLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(btnClear, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(btnOutputCopy, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(btnOutputToInput, javax.swing.GroupLayout.DEFAULT_SIZE, 164, Short.MAX_VALUE))
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
        pnlEncode.setLayout(new java.awt.GridLayout(5, 0));

        btnGrpEncodeType.add(rdoAll);
        rdoAll.setText("All");
        rdoAll.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                rdoAllActionPerformed(evt);
            }
        });
        pnlEncode.add(rdoAll);

        btnGrpEncodeType.add(rdoAlphaNum);
        rdoAlphaNum.setSelected(true);
        rdoAlphaNum.setText("Alphanum");
        rdoAlphaNum.setToolTipText("[^A-Za-z0-9]");
        rdoAlphaNum.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                rdoAlphaNumActionPerformed(evt);
            }
        });
        pnlEncode.add(rdoAlphaNum);

        btnGrpEncodeType.add(rdoURLSafe);
        rdoURLSafe.setText("Burp Like");
        rdoURLSafe.setToolTipText("[^A-Za-z0-9!\\\"$'()*,/:<>@\\[\\\\\\]^`{|},.~-]");
        rdoURLSafe.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                rdoURLSafeActionPerformed(evt);
            }
        });
        pnlEncode.add(rdoURLSafe);

        btnGrpEncodeType.add(rdoLigth);
        rdoLigth.setText("Light");
        rdoLigth.setToolTipText("[^A-Za-z0-9!\\\"$&'()*+,:=@|~]");
        rdoLigth.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                rdoLigthActionPerformed(evt);
            }
        });
        pnlEncode.add(rdoLigth);

        btnGrpEncodeType.add(rdoStandard);
        rdoStandard.setText("Standard");
        rdoStandard.setToolTipText("[^A-Za-z0-9!\\\"'()*,/:<>@\\[\\\\\\]^`{|}~]");
        pnlEncode.add(rdoStandard);

        pnlSelectOption.add(pnlEncode);

        pnlConvertCase.setBorder(javax.swing.BorderFactory.createTitledBorder("Convert Case"));
        pnlConvertCase.setLayout(new java.awt.GridLayout(4, 0));

        btnConvertCase.add(rdoLowerCase);
        rdoLowerCase.setSelected(true);
        rdoLowerCase.setText("Lower Case");
        rdoLowerCase.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                rdoLowerCaseActionPerformed(evt);
            }
        });
        pnlConvertCase.add(rdoLowerCase);

        btnConvertCase.add(rdoUpperCase);
        rdoUpperCase.setText("Upper Case");
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

        pnlTransAction.setLayout(new javax.swing.BoxLayout(pnlTransAction, javax.swing.BoxLayout.PAGE_AXIS));

        pnlEncodeDecode.setBorder(javax.swing.BorderFactory.createTitledBorder("Encode/Decode"));
        pnlEncodeDecode.setLayout(new java.awt.GridLayout(15, 0, 1, 1));

        btnSmartDecode.setText("Smart Decode");
        btnSmartDecode.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnSmartDecodeActionPerformed(evt);
            }
        });
        pnlEncodeDecode.add(btnSmartDecode);

        pnlEncDec.setLayout(new java.awt.GridLayout(1, 1));

        btnEncode.setMnemonic('E');
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

        btnDecode.setMnemonic('D');
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

        chk76Newline.setText("76 newline");
        chk76Newline.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                chk76NewlineActionPerformed(evt);
            }
        });
        pnlBase64.add(chk76Newline);

        chk64Newline.setText("64 newline");
        chk64Newline.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                chk64NewlineActionPerformed(evt);
            }
        });
        pnlBase64.add(chk64Newline);

        chkPadding.setSelected(true);
        chkPadding.setText("Padding");
        pnlBase64.add(chkPadding);

        pnlEncodeDecode.add(pnlBase64);

        pnlBase64URLSafe.setLayout(new java.awt.GridLayout(1, 1));

        rdoEncodeDecodeGrp.add(rdoBase64URLSafe);
        rdoBase64URLSafe.setText("Base64URLSafe");
        pnlBase64URLSafe.add(rdoBase64URLSafe);

        rdoEncodeDecodeGrp.add(rdoBase64andURL);
        rdoBase64andURL.setText("Base64 + URL");
        pnlBase64URLSafe.add(rdoBase64andURL);

        pnlEncodeDecode.add(pnlBase64URLSafe);

        pnlBaseN.setLayout(new java.awt.GridLayout(1, 0));

        rdoEncodeDecodeGrp.add(rdoBase32);
        rdoBase32.setText("Base32");
        pnlBaseN.add(rdoBase32);

        rdoEncodeDecodeGrp.add(rdoBase16);
        rdoBase16.setText("Base16");
        pnlBaseN.add(rdoBase16);

        chkNPadding.setSelected(true);
        chkNPadding.setText("Padding");
        pnlBaseN.add(chkNPadding);

        pnlEncodeDecode.add(pnlBaseN);

        pnlMail.setLayout(new java.awt.GridLayout(1, 2));

        rdoEncodeDecodeGrp.add(rdoQuotedPrintable);
        rdoQuotedPrintable.setText("QuotedPrintable");
        pnlMail.add(rdoQuotedPrintable);

        pnlEncodeDecode.add(pnlMail);

        rdoEncodeDecodeGrp.add(rdoPunycode);
        rdoPunycode.setText("puyencode");
        pnlEncodeDecode.add(rdoPunycode);

        pnlHtmlEnc.setLayout(new java.awt.GridLayout(1, 4));

        rdoEncodeDecodeGrp.add(rdoHtml);
        rdoHtml.setText("HTML(<,>,&,\",')");
        pnlHtmlEnc.add(rdoHtml);

        rdoEncodeDecodeGrp.add(rdoHtmlDec);
        rdoHtmlDec.setText("&#d;");
        pnlHtmlEnc.add(rdoHtmlDec);

        pnlEncodeDecode.add(pnlHtmlEnc);

        pnlHtmlHex.setLayout(new java.awt.GridLayout(1, 2));

        rdoEncodeDecodeGrp.add(rdoHtmlUnicode);
        rdoHtmlUnicode.setText("&#xhh;(unicode)");
        pnlHtmlHex.add(rdoHtmlUnicode);

        rdoEncodeDecodeGrp.add(rdoHtmlByteHex);
        rdoHtmlByteHex.setText("&#xhh;(byte)");
        pnlHtmlHex.add(rdoHtmlByteHex);

        pnlEncodeDecode.add(pnlHtmlHex);

        pnlJSUnicodeEnc.setLayout(new java.awt.GridLayout(1, 1));

        rdoEncodeDecodeGrp.add(rdoUnicodeHex);
        rdoUnicodeHex.setText("\\uhhhh");
        pnlJSUnicodeEnc.add(rdoUnicodeHex);

        rdoEncodeDecodeGrp.add(rdoUnicodeHex2);
        rdoUnicodeHex2.setText("$hhhh");
        pnlJSUnicodeEnc.add(rdoUnicodeHex2);

        pnlEncodeDecode.add(pnlJSUnicodeEnc);

        pnlJSHexEnc.setLayout(new java.awt.GridLayout(1, 1));

        rdoEncodeDecodeGrp.add(rdoByteNoneHex);
        rdoByteNoneHex.setText("hh(hex)");
        pnlJSHexEnc.add(rdoByteNoneHex);

        rdoEncodeDecodeGrp.add(rdoByteXHex);
        rdoByteXHex.setText("\\xhh(hex)");
        pnlJSHexEnc.add(rdoByteXHex);

        rdoEncodeDecodeGrp.add(rdoByteHex2);
        rdoByteHex2.setText("\\h(hex)");
        pnlJSHexEnc.add(rdoByteHex2);

        rdoEncodeDecodeGrp.add(rdoByteOct);
        rdoByteOct.setText("\\ooo(oct)");
        pnlJSHexEnc.add(rdoByteOct);

        pnlEncodeDecode.add(pnlJSHexEnc);

        pnlCompress.setLayout(new java.awt.GridLayout(1, 2));

        rdoEncodeDecodeGrp.add(rdoGzip);
        rdoGzip.setText("Gzip");
        pnlCompress.add(rdoGzip);

        rdoEncodeDecodeGrp.add(rdoZLIB);
        rdoZLIB.setText("Zlib");
        pnlCompress.add(rdoZLIB);

        rdoEncodeDecodeGrp.add(rdoZLIB_NOWRAP);
        rdoZLIB_NOWRAP.setText("Zlib(with Gzip)");
        pnlCompress.add(rdoZLIB_NOWRAP);

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

        pnlLang.setLayout(new java.awt.GridLayout(1, 4));

        rdoEncodeDecodeGrp.add(rdoCLang);
        rdoCLang.setText("C Lang");
        pnlLang.add(rdoCLang);

        rdoEncodeDecodeGrp.add(rdoJSON);
        rdoJSON.setText("JSON");
        pnlLang.add(rdoJSON);

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

        chkMetaChar.setText("Metachar");
        pnlLang.add(chkMetaChar);

        pnlEncodeDecode.add(pnlLang);

        pnlTransAction.add(pnlEncodeDecode);

        pnlFormat.setBorder(javax.swing.BorderFactory.createTitledBorder("Format"));
        pnlFormat.setLayout(new java.awt.GridLayout(1, 3));

        rdoFormatGrp.add(rdoMinifyFormat);
        rdoMinifyFormat.setText("Minify");
        pnlFormat.add(rdoMinifyFormat);

        rdoFormatGrp.add(rdoBeautifyFormat);
        rdoBeautifyFormat.setSelected(true);
        rdoBeautifyFormat.setText("Beautify");
        pnlFormat.add(rdoBeautifyFormat);

        btnSmartFormat.setText("Smart Format");
        btnSmartFormat.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnSmartFormatActionPerformed(evt);
            }
        });
        pnlFormat.add(btnSmartFormat);

        pnlTransAction.add(pnlFormat);

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

        pnlTransAction.add(pnlRegex);

        tabbetTransAction.addTab("Encode/Decode", pnlTransAction);

        pnlHashCheckSum.setLayout(new javax.swing.BoxLayout(pnlHashCheckSum, javax.swing.BoxLayout.PAGE_AXIS));

        pnlHashTrans.setBorder(javax.swing.BorderFactory.createTitledBorder("Hash"));
        pnlHashTrans.setLayout(new java.awt.GridLayout(24, 3));

        btnHashMd2.setText("md2");
        btnHashMd2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashMd2ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashMd2);

        btnHashMd4.setText("md4");
        btnHashMd4.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashMd4ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashMd4);

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

        btnHashSha224.setText("sha224");
        btnHashSha224.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashSha224ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashSha224);

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

        btnHashSha512_224.setText("sha512/224");
        btnHashSha512_224.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashSha512_224ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashSha512_224);

        btnHashSha512_256.setText("sha512/256");
        btnHashSha512_256.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashSha512_256ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashSha512_256);

        btnHashSha3_224.setText("sha3-224");
        btnHashSha3_224.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashSha3_224ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashSha3_224);

        btnHashSha3_256.setText("sha3-256");
        btnHashSha3_256.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashSha3_256ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashSha3_256);

        btnHashSha3_384.setText("sha3-384");
        btnHashSha3_384.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashSha3_384ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashSha3_384);

        btnHashSha3_512.setText("sha3-512");
        btnHashSha3_512.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashSha3_512ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashSha3_512);

        btnHashSHAKE128.setText("SHAKE128");
        btnHashSHAKE128.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashSHAKE128ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashSHAKE128);

        btnHashSHAKE256.setText("SHAKE256");
        btnHashSHAKE256.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashSHAKE256ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashSHAKE256);

        btnHashSKEIN256_128.setText("SKEIN-256-128");
        btnHashSKEIN256_128.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashSKEIN256_128ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashSKEIN256_128);

        btnHashSKEIN256_160.setText("SKEIN-256-160");
        btnHashSKEIN256_160.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashSKEIN256_160ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashSKEIN256_160);

        btnHashSKEIN256_224.setText("SKEIN-256-224");
        btnHashSKEIN256_224.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashSKEIN256_224ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashSKEIN256_224);

        btnHashSKEIN256_256.setText("SKEIN-256-256");
        btnHashSKEIN256_256.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashSKEIN256_256ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashSKEIN256_256);

        btnHashSKEIN512_128.setText("SKEIN-512-128");
        btnHashSKEIN512_128.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashSKEIN512_128ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashSKEIN512_128);

        btnHashSKEIN512_160.setText("SKEIN-512-160");
        btnHashSKEIN512_160.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashSKEIN512_160ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashSKEIN512_160);

        btnHashSKEIN512_224.setText("SKEIN-512-224");
        btnHashSKEIN512_224.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashSKEIN512_224ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashSKEIN512_224);

        btnHashSKEIN512_256.setText("SKEIN-512-256");
        btnHashSKEIN512_256.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashSKEIN512_256ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashSKEIN512_256);

        btnHashSKEIN512_384.setText("SKEIN-512-384");
        btnHashSKEIN512_384.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashSKEIN512_384ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashSKEIN512_384);

        btnHashSKEIN512_512.setText("SKEIN-512-512");
        btnHashSKEIN512_512.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashSKEIN512_512ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashSKEIN512_512);

        btnHashSKEIN1024_384.setText("SKEIN-1024-384");
        btnHashSKEIN1024_384.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashSKEIN1024_384ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashSKEIN1024_384);

        btnHashSKEIN1024_512.setText("SKEIN-1024-512");
        btnHashSKEIN1024_512.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashSKEIN1024_512ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashSKEIN1024_512);

        btnHashSKEIN1024_1024.setText("SKEIN-1024-1024");
        btnHashSKEIN1024_1024.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashSKEIN1024_1024ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashSKEIN1024_1024);

        btnHashKECCAK224.setText("KECCAK-224");
        btnHashKECCAK224.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashKECCAK224ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashKECCAK224);

        btnHashKECCAK256.setText("KECCAK-256");
        btnHashKECCAK256.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashKECCAK256ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashKECCAK256);

        btnHashKECCAK288.setText("KECCAK-288");
        btnHashKECCAK288.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashKECCAK288ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashKECCAK288);

        btnHashKECCAK384.setText("KECCAK-384");
        btnHashKECCAK384.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashKECCAK384ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashKECCAK384);

        btnHashKECCAK512.setText("KECCAK-512");
        btnHashKECCAK512.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashKECCAK512ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashKECCAK512);

        btnHashHARAKA256.setText("HARAKA-256");
        btnHashHARAKA256.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashHARAKA256ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashHARAKA256);

        btnHashHARAKA512.setText("HARAKA-512");
        btnHashHARAKA512.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashHARAKA512ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashHARAKA512);

        btnHashRIPEMD128.setText("RIPEMD128");
        btnHashRIPEMD128.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashRIPEMD128ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashRIPEMD128);

        btnHashRIPEMD129.setText("RIPEMD160");
        btnHashRIPEMD129.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashRIPEMD160ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashRIPEMD129);

        btnHashRIPEMD256.setText("RIPEMD256");
        btnHashRIPEMD256.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashRIPEMD256ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashRIPEMD256);

        btnHashRIPEMD320.setText("RIPEMD320");
        btnHashRIPEMD320.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashRIPEMD320ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashRIPEMD320);

        btnHashGOST3411.setText("GOST3411");
        btnHashGOST3411.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashGOST3411ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashGOST3411);

        btnHashGOST3411_2012_256.setText("GOST2012-256");
        btnHashGOST3411_2012_256.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashGOST3411_2012_256ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashGOST3411_2012_256);

        btnHashGOST3411_2012_512.setText("GOST2012-512");
        btnHashGOST3411_2012_512.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashGOST3411_2012_512ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashGOST3411_2012_512);

        btnHashDSTU7564_256.setText("DSTU7564-256");
        btnHashDSTU7564_256.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashDSTU7564_256ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashDSTU7564_256);

        btnHashDSTU7564_384.setText("DSTU7564-384");
        btnHashDSTU7564_384.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashDSTU7564_384ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashDSTU7564_384);

        btnHashDSTU7564_512.setText("DSTU7564-512");
        btnHashDSTU7564_512.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashDSTU7564_512ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashDSTU7564_512);

        btnHashBLAKE2B_160.setText("BLAKE2B-160");
        btnHashBLAKE2B_160.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashBLAKE2B_160ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashBLAKE2B_160);

        btnHashBLAKE2B_256.setText("BLAKE2B-256");
        btnHashBLAKE2B_256.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashBLAKE2B_256ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashBLAKE2B_256);

        btnHashBLAKE2B_384.setText("BLAKE2B-384");
        btnHashBLAKE2B_384.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashBLAKE2B_384ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashBLAKE2B_384);

        btnHashBLAKE2B_512.setText("BLAKE2B-512");
        btnHashBLAKE2B_512.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashBLAKE2B_512ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashBLAKE2B_512);

        btnHashBLAKE2S_128.setText("BLAKE2S-128");
        btnHashBLAKE2S_128.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashBLAKE2S_128ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashBLAKE2S_128);

        btnHashBLAKE2S_160.setText("BLAKE2S-160");
        btnHashBLAKE2S_160.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashBLAKE2S_160ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashBLAKE2S_160);

        btnHashBLAKE2_S224.setText("BLAKE2S-224");
        btnHashBLAKE2_S224.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashBLAKE2_S224ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashBLAKE2_S224);

        btnHashBLAKE2S_256.setText("BLAKE2S-256");
        btnHashBLAKE2S_256.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashBLAKE2S_256ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashBLAKE2S_256);

        btnHashBLAKE3_256.setText("BLAKE3-256");
        btnHashBLAKE3_256.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashBLAKE3_256ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashBLAKE3_256);

        btnHashPARALLELHASH128_256.setText("PARALLEL128-256");
        btnHashPARALLELHASH128_256.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashPARALLELHASH128_256ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashPARALLELHASH128_256);

        btnHashPARALLELHASH256_512.setText("PARALLEL256-512");
        btnHashPARALLELHASH256_512.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashPARALLELHASH256_512ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashPARALLELHASH256_512);

        btnHashTiger.setText("Tiger");
        btnHashTiger.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashTigerActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashTiger);

        btnHashWHIRLPOOL.setText("WHIRLPOOL");
        btnHashWHIRLPOOL.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashWHIRLPOOLActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashWHIRLPOOL);

        btnHashSM3.setText("SM3");
        btnHashSM3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashSM3ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashSM3);

        btnHashTUPLEHASH128_256.setText("TUPLE128-256");
        btnHashTUPLEHASH128_256.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashTUPLEHASH128_256ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashTUPLEHASH128_256);

        btnHashTUPLEHASH256_512.setText("TUPLE256-512");
        btnHashTUPLEHASH256_512.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashTUPLEHASH256_512ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashTUPLEHASH256_512);

        btnHashISAP.setText("ISAP");
        btnHashISAP.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashISAPActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashISAP);

        btnHashAscon.setText("AsconHash");
        btnHashAscon.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashAsconActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashAscon);

        btnHashAsconA.setText("AsconHashA");
        btnHashAsconA.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashAsconAActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashAsconA);

        btnHashAsconXof.setText("AsconXof");
        btnHashAsconXof.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashAsconXofActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashAsconXof);

        btnHashAsconXofA.setText("AsconXofA");
        btnHashAsconXofA.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashAsconXofAActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashAsconXofA);

        btnHashESCH256.setText("ESCH256");
        btnHashESCH256.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashESCH256ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashESCH256);

        btnHashESCH384.setText("ESCH384");
        btnHashESCH384.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashESCH384ActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashESCH384);

        btnHashPhotonBeetle.setText("PhotonBeetle");
        btnHashPhotonBeetle.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashPhotonBeetleActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashPhotonBeetle);

        btnHashXoodyak.setText("Xoodyak");
        btnHashXoodyak.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHashXoodyakActionPerformed(evt);
            }
        });
        pnlHashTrans.add(btnHashXoodyak);

        pnlHashCheckSum.add(pnlHashTrans);

        pnlCheckSumTrans.setBorder(javax.swing.BorderFactory.createTitledBorder("CheckSum"));
        pnlCheckSumTrans.setLayout(new java.awt.GridLayout(3, 3));

        btnCRC32.setText("CRC32");
        btnCRC32.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnCRC32ActionPerformed(evt);
            }
        });
        pnlCheckSumTrans.add(btnCRC32);

        btnCRC32C.setText("CRC32C");
        btnCRC32C.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnCRC32CActionPerformed(evt);
            }
        });
        pnlCheckSumTrans.add(btnCRC32C);

        btnAdler32.setText("Adler32");
        btnAdler32.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnAdler32ActionPerformed(evt);
            }
        });
        pnlCheckSumTrans.add(btnAdler32);

        btnMurmurHash2_32.setText("Murmur2/32");
        btnMurmurHash2_32.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnMurmurHash2_32ActionPerformed(evt);
            }
        });
        pnlCheckSumTrans.add(btnMurmurHash2_32);

        btnMurmurHash2_64.setText("Murmur2/64");
        btnMurmurHash2_64.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnMurmurHash2_64ActionPerformed(evt);
            }
        });
        pnlCheckSumTrans.add(btnMurmurHash2_64);

        btnXXHash32.setText("xxHash32");
        btnXXHash32.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnXXHash32ActionPerformed(evt);
            }
        });
        pnlCheckSumTrans.add(btnXXHash32);

        btnMurmurHash3_32x86.setText("Murmur3/32x86");
        btnMurmurHash3_32x86.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnMurmurHash3_32x86ActionPerformed(evt);
            }
        });
        pnlCheckSumTrans.add(btnMurmurHash3_32x86);

        btnMurmurHash3_128x64.setText("Murmur3/128x64");
        btnMurmurHash3_128x64.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnMurmurHash3_128x64ActionPerformed(evt);
            }
        });
        pnlCheckSumTrans.add(btnMurmurHash3_128x64);

        pnlHashCheckSum.add(pnlCheckSumTrans);

        tabbetTransAction.addTab("Hash/Checksum", pnlHashCheckSum);

        tabTransrator.add(tabbetTransAction, java.awt.BorderLayout.EAST);

        tabbetTranscoder.addTab("Translator", tabTransrator);

        tabGenerator.setLayout(new java.awt.BorderLayout());

        splitGenerator.setOrientation(javax.swing.JSplitPane.VERTICAL_SPLIT);

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
                        .addComponent(lblNumFormat))
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
                .addContainerGap(1136, Short.MAX_VALUE))
        );
        pnlNumbersLayout.setVerticalGroup(
            pnlNumbersLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlNumbersLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(pnlNumbersLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(txtNumFormat, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(lblNumFormat))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(pnlNumbersLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblNumStart)
                    .addComponent(spnNumStart, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(pnlNumbersLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblNumEnd)
                    .addComponent(spnNumEnd, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(pnlNumbersLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblNumStep)
                    .addComponent(spnNumStep, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(832, Short.MAX_VALUE))
        );

        tabbetSequence.addTab("Numbers", pnlNumbers);

        txtDateFormat.setText("yyyy/MM/dd");

        lblDateFormat.setText("(DateTimeFormatter pattern)");

        lblDateStart.setText("Start:");

        lblDateEnd.setText("End:");

        lblDateStep.setText("Stop:");

        cmbDateUnit.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "DAYS", "WEEKS", "MONTHS", "YEARS" }));

        spnDateStep.setModel(new javax.swing.SpinnerNumberModel(1, null, null, 1));

        spnDateStart.setModel(new javax.swing.SpinnerDateModel());
        spnDateStart.setToolTipText("");
        spnDateStart.setEditor(new javax.swing.JSpinner.DateEditor(spnDateStart, "yyyy/MM/dd"));
        spnDateStart.setRequestFocusEnabled(false);

        spnDateEnd.setModel(new javax.swing.SpinnerDateModel());
        spnDateEnd.setToolTipText("");
        spnDateEnd.setEditor(new javax.swing.JSpinner.DateEditor(spnDateEnd, "yyyy/MM/dd"));
        spnDateEnd.setRequestFocusEnabled(false);

        javax.swing.GroupLayout pnlDateLayout = new javax.swing.GroupLayout(pnlDate);
        pnlDate.setLayout(pnlDateLayout);
        pnlDateLayout.setHorizontalGroup(
            pnlDateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlDateLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(pnlDateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(pnlDateLayout.createSequentialGroup()
                        .addComponent(txtDateFormat, javax.swing.GroupLayout.PREFERRED_SIZE, 300, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(lblDateFormat))
                    .addGroup(pnlDateLayout.createSequentialGroup()
                        .addGroup(pnlDateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(lblDateEnd)
                            .addComponent(lblDateStep)
                            .addComponent(lblDateStart))
                        .addGap(18, 18, 18)
                        .addGroup(pnlDateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(spnDateStart, javax.swing.GroupLayout.PREFERRED_SIZE, 257, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addGroup(pnlDateLayout.createSequentialGroup()
                                .addComponent(spnDateStep, javax.swing.GroupLayout.PREFERRED_SIZE, 77, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(18, 18, 18)
                                .addComponent(cmbDateUnit, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addComponent(spnDateEnd, javax.swing.GroupLayout.PREFERRED_SIZE, 257, javax.swing.GroupLayout.PREFERRED_SIZE))))
                .addContainerGap(1092, Short.MAX_VALUE))
        );
        pnlDateLayout.setVerticalGroup(
            pnlDateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlDateLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(pnlDateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(txtDateFormat, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(lblDateFormat))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(pnlDateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblDateStart)
                    .addComponent(spnDateStart, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(pnlDateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(spnDateEnd, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(lblDateEnd))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(pnlDateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(cmbDateUnit, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(pnlDateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(lblDateStep)
                        .addComponent(spnDateStep, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(832, Short.MAX_VALUE))
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
                .addContainerGap(1061, Short.MAX_VALUE))
        );
        tabRandomLayout.setVerticalGroup(
            tabRandomLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, tabRandomLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(pnlCharacter, javax.swing.GroupLayout.DEFAULT_SIZE, 934, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(tabRandomLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(pnlCount, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(pnlStringLength, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap())
        );

        tabbetGenerate.addTab("Random", tabRandom);

        pnlGenerateKey.setLayout(new java.awt.BorderLayout());

        lbAlgorithm.setText("Algorithm:");

        lblKeySize.setText("KeySize;");

        cmbAlgorithm.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                cmbAlgorithmItemStateChanged(evt);
            }
        });

        pnlKeySize.setLayout(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT));

        javax.swing.GroupLayout pnlKeyPairAlgorithmLayout = new javax.swing.GroupLayout(pnlKeyPairAlgorithm);
        pnlKeyPairAlgorithm.setLayout(pnlKeyPairAlgorithmLayout);
        pnlKeyPairAlgorithmLayout.setHorizontalGroup(
            pnlKeyPairAlgorithmLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlKeyPairAlgorithmLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(pnlKeyPairAlgorithmLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(lbAlgorithm)
                    .addComponent(lblKeySize))
                .addGap(11, 11, 11)
                .addGroup(pnlKeyPairAlgorithmLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(pnlKeyPairAlgorithmLayout.createSequentialGroup()
                        .addComponent(cmbAlgorithm, javax.swing.GroupLayout.PREFERRED_SIZE, 130, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(lblKeyPairValid, javax.swing.GroupLayout.DEFAULT_SIZE, 670, Short.MAX_VALUE)
                        .addContainerGap(674, Short.MAX_VALUE))
                    .addGroup(pnlKeyPairAlgorithmLayout.createSequentialGroup()
                        .addComponent(pnlKeySize, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addContainerGap())))
        );
        pnlKeyPairAlgorithmLayout.setVerticalGroup(
            pnlKeyPairAlgorithmLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, pnlKeyPairAlgorithmLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(pnlKeyPairAlgorithmLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addGroup(pnlKeyPairAlgorithmLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(lbAlgorithm)
                        .addComponent(cmbAlgorithm, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addComponent(lblKeyPairValid, javax.swing.GroupLayout.PREFERRED_SIZE, 24, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(pnlKeyPairAlgorithmLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(pnlKeySize, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(lblKeySize, javax.swing.GroupLayout.DEFAULT_SIZE, 28, Short.MAX_VALUE))
                .addContainerGap())
        );

        pnlGenerateKey.add(pnlKeyPairAlgorithm, java.awt.BorderLayout.NORTH);

        btnGrpExportKeyPair.add(rdoConvertKeyPairPEM);
        rdoConvertKeyPairPEM.setSelected(true);
        rdoConvertKeyPairPEM.setText("KeyPair in PEM format");

        btnGrpExportKeyPair.add(rdoConvertKeyPairJWK);
        rdoConvertKeyPairJWK.setText("KeyPair in JWK format");

        javax.swing.GroupLayout pnlKeyPairConvertFormatLayout = new javax.swing.GroupLayout(pnlKeyPairConvertFormat);
        pnlKeyPairConvertFormat.setLayout(pnlKeyPairConvertFormatLayout);
        pnlKeyPairConvertFormatLayout.setHorizontalGroup(
            pnlKeyPairConvertFormatLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlKeyPairConvertFormatLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(pnlKeyPairConvertFormatLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(rdoConvertKeyPairJWK)
                    .addComponent(rdoConvertKeyPairPEM))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        pnlKeyPairConvertFormatLayout.setVerticalGroup(
            pnlKeyPairConvertFormatLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlKeyPairConvertFormatLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(rdoConvertKeyPairPEM)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(rdoConvertKeyPairJWK)
                .addContainerGap(875, Short.MAX_VALUE))
        );

        pnlGenerateKey.add(pnlKeyPairConvertFormat, java.awt.BorderLayout.CENTER);

        tabbetGenerate.addTab("GenerateKeyPair", pnlGenerateKey);

        pnlTop.add(tabbetGenerate, java.awt.BorderLayout.CENTER);

        btnGenerate.setText("Generate");
        btnGenerate.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnGenerateActionPerformed(evt);
            }
        });

        btnGeneCopy.setText("Output Copy");
        btnGeneCopy.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnGeneCopyActionPerformed(evt);
            }
        });

        btnGeneSavetoFile.setText("Save to file");
        btnGeneSavetoFile.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnGeneSavetoFileActionPerformed(evt);
            }
        });

        btnGeneClear.setText("Clear");
        btnGeneClear.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnGeneClearActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout pnlRightLayout = new javax.swing.GroupLayout(pnlRight);
        pnlRight.setLayout(pnlRightLayout);
        pnlRightLayout.setHorizontalGroup(
            pnlRightLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlRightLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(pnlRightLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(btnGeneCopy, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(btnGenerate, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(btnGeneSavetoFile, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(btnGeneClear, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap())
        );
        pnlRightLayout.setVerticalGroup(
            pnlRightLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pnlRightLayout.createSequentialGroup()
                .addGap(29, 29, 29)
                .addComponent(btnGenerate)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(btnGeneClear)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(btnGeneCopy)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(btnGeneSavetoFile)
                .addContainerGap(897, Short.MAX_VALUE))
        );

        pnlTop.add(pnlRight, java.awt.BorderLayout.EAST);

        splitGenerator.setTopComponent(pnlTop);

        pnlBottom.setLayout(new java.awt.BorderLayout());

        txtGenarate.setColumns(20);
        txtGenarate.setRows(5);
        scrollGenerate.setViewportView(txtGenarate);

        pnlBottom.add(scrollGenerate, java.awt.BorderLayout.CENTER);

        splitGenerator.setBottomComponent(pnlBottom);

        tabGenerator.add(splitGenerator, java.awt.BorderLayout.CENTER);

        tabbetTranscoder.addTab("Generater", tabGenerator);

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

        jLabel2.setText("Character kind");

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
                                .addGap(0, 491, Short.MAX_VALUE))
                            .addComponent(jLabel3, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
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
                .addContainerGap()
                .addGroup(tabTokenStrengthLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 196, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(btnAnalyze))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(tabTokenStrengthLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(tabTokenStrengthLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(jLabel4)
                        .addComponent(jLabel2))
                    .addComponent(jLabel3))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(tabTokenStrengthLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(txtBase, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(tabTokenStrengthLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(txtStrength, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(btnCalc)
                        .addComponent(txtExponent, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(lblmaximum)
                        .addComponent(jLabel1)))
                .addContainerGap(890, Short.MAX_VALUE))
        );

        tabbetTranscoder.addTab("Token strength", tabTokenStrength);

        lblUnixtime.setText("Unixtime:");

        btnUnixtimeCopy.setText("Copy");
        btnUnixtimeCopy.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnUnixtimeCopyActionPerformed(evt);
            }
        });

        lblJavaSerial.setText("Java serial:");

        btnJavaSerialCopy.setText("Copy");
        btnJavaSerialCopy.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnJavaSerialCopyActionPerformed(evt);
            }
        });

        lblExcelSerial.setText("Excel serial:");

        btnExcelSerial.setText("Copy");
        btnExcelSerial.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnExcelSerialActionPerformed(evt);
            }
        });

        lblZoneDate.setText("ZoneDate:");

        spnZoneDateTime.setModel(new javax.swing.SpinnerDateModel());
        spnZoneDateTime.setToolTipText("");
        spnZoneDateTime.setEditor(new javax.swing.JSpinner.DateEditor(spnZoneDateTime, "yyyy/MM/dd HH:mm:ss"));
        spnZoneDateTime.setMinimumSize(new java.awt.Dimension(180, 22));
        spnZoneDateTime.setName(""); // NOI18N
        spnZoneDateTime.setPreferredSize(new java.awt.Dimension(200, 22));
        spnZoneDateTime.setRequestFocusEnabled(false);

        cmbTimezone.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                cmbTimezoneItemStateChanged(evt);
            }
        });
        cmbTimezone.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cmbTimezoneActionPerformed(evt);
            }
        });

        txtExcelSerial.setFormatterFactory(new javax.swing.text.DefaultFormatterFactory(new javax.swing.text.NumberFormatter(new java.text.DecimalFormat("####.000000"))));
        txtExcelSerial.setHorizontalAlignment(javax.swing.JTextField.TRAILING);
        txtExcelSerial.setToolTipText("");
        txtExcelSerial.setMinimumSize(new java.awt.Dimension(180, 22));
        txtExcelSerial.setName(""); // NOI18N
        txtExcelSerial.setPreferredSize(new java.awt.Dimension(200, 22));
        txtExcelSerial.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                txtExcelSerialFocusLost(evt);
            }
        });

        txtJavaSerial.setFormatterFactory(new javax.swing.text.DefaultFormatterFactory(new javax.swing.text.NumberFormatter(new java.text.DecimalFormat("#0"))));
        txtJavaSerial.setHorizontalAlignment(javax.swing.JTextField.TRAILING);
        txtJavaSerial.setToolTipText("");
        txtJavaSerial.setMinimumSize(new java.awt.Dimension(180, 22));
        txtJavaSerial.setName(""); // NOI18N
        txtJavaSerial.setPreferredSize(new java.awt.Dimension(200, 22));
        txtJavaSerial.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                txtJavaSerialFocusLost(evt);
            }
        });

        txtUnixtime.setFormatterFactory(new javax.swing.text.DefaultFormatterFactory(new javax.swing.text.NumberFormatter(new java.text.DecimalFormat("#0"))));
        txtUnixtime.setHorizontalAlignment(javax.swing.JTextField.TRAILING);
        txtUnixtime.setToolTipText("");
        txtUnixtime.setMinimumSize(new java.awt.Dimension(180, 22));
        txtUnixtime.setName(""); // NOI18N
        txtUnixtime.setPreferredSize(new java.awt.Dimension(200, 22));
        txtUnixtime.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                txtUnixtimeFocusLost(evt);
            }
        });

        lblDate.setText("Date(+0000):");

        btnZoneDateCopy.setText("Copy");
        btnZoneDateCopy.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnZoneDateCopyActionPerformed(evt);
            }
        });

        txtSystemZoneDate.setMinimumSize(new java.awt.Dimension(180, 22));
        txtSystemZoneDate.setName(""); // NOI18N
        txtSystemZoneDate.setPreferredSize(new java.awt.Dimension(200, 22));
        txtSystemZoneDate.setRequestFocusEnabled(false);

        lblDateGMT.setText("Date(GMT):");

        txtSystemZoneDateGMT.setEditable(false);
        txtSystemZoneDateGMT.setMinimumSize(new java.awt.Dimension(180, 22));
        txtSystemZoneDateGMT.setName(""); // NOI18N
        txtSystemZoneDateGMT.setPreferredSize(new java.awt.Dimension(200, 22));
        txtSystemZoneDateGMT.setRequestFocusEnabled(false);

        btnZoneDateGMTCopy.setText("Copy");
        btnZoneDateGMTCopy.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnZoneDateGMTCopyActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout tabDateConverterLayout = new javax.swing.GroupLayout(tabDateConverter);
        tabDateConverter.setLayout(tabDateConverterLayout);
        tabDateConverterLayout.setHorizontalGroup(
            tabDateConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(tabDateConverterLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(tabDateConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(lblDateGMT, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(lblJavaSerial, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(lblUnixtime, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(lblZoneDate)
                    .addComponent(lblDate, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(lblExcelSerial, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(tabDateConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(txtJavaSerial, javax.swing.GroupLayout.DEFAULT_SIZE, 1272, Short.MAX_VALUE)
                    .addComponent(txtUnixtime, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(txtExcelSerial, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(txtSystemZoneDate, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(spnZoneDateTime, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(txtSystemZoneDateGMT, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(tabDateConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(btnUnixtimeCopy, javax.swing.GroupLayout.PREFERRED_SIZE, 90, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(btnJavaSerialCopy, javax.swing.GroupLayout.PREFERRED_SIZE, 90, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(btnZoneDateCopy, javax.swing.GroupLayout.PREFERRED_SIZE, 90, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(btnExcelSerial, javax.swing.GroupLayout.PREFERRED_SIZE, 90, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(cmbTimezone, javax.swing.GroupLayout.PREFERRED_SIZE, 300, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(btnZoneDateGMTCopy, javax.swing.GroupLayout.PREFERRED_SIZE, 90, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap())
        );
        tabDateConverterLayout.setVerticalGroup(
            tabDateConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(tabDateConverterLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(tabDateConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(tabDateConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addComponent(cmbTimezone, javax.swing.GroupLayout.PREFERRED_SIZE, 30, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(lblZoneDate, javax.swing.GroupLayout.Alignment.TRAILING))
                    .addComponent(spnZoneDateTime, javax.swing.GroupLayout.PREFERRED_SIZE, 30, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(tabDateConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblDateGMT)
                    .addComponent(txtSystemZoneDateGMT, javax.swing.GroupLayout.PREFERRED_SIZE, 28, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(btnZoneDateGMTCopy, javax.swing.GroupLayout.PREFERRED_SIZE, 28, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(tabDateConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.CENTER)
                    .addComponent(lblDate)
                    .addComponent(txtSystemZoneDate, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.PREFERRED_SIZE, 28, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(btnZoneDateCopy, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 28, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(tabDateConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.CENTER)
                    .addComponent(lblUnixtime)
                    .addComponent(txtUnixtime, javax.swing.GroupLayout.PREFERRED_SIZE, 28, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(btnUnixtimeCopy, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.PREFERRED_SIZE, 28, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(tabDateConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.CENTER)
                    .addComponent(lblJavaSerial)
                    .addComponent(txtJavaSerial, javax.swing.GroupLayout.PREFERRED_SIZE, 28, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(btnJavaSerialCopy, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 28, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(tabDateConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.CENTER)
                    .addComponent(lblExcelSerial)
                    .addComponent(txtExcelSerial, javax.swing.GroupLayout.PREFERRED_SIZE, 28, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(btnExcelSerial, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 28, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(392, 392, 392))
        );

        tabbetConverter.addTab("Date", tabDateConverter);

        lblBin.setText("Bin:");

        lblOct.setText("Oct:");

        lblDec.setText("Dec:");

        lblHex.setText("Hex:");

        lblRadix32.setText("Radix32:");

        txtBin.setHorizontalAlignment(javax.swing.JTextField.RIGHT);
        txtBin.setText("0");
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

        javax.swing.GroupLayout tabBaseConverterLayout = new javax.swing.GroupLayout(tabBaseConverter);
        tabBaseConverter.setLayout(tabBaseConverterLayout);
        tabBaseConverterLayout.setHorizontalGroup(
            tabBaseConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(tabBaseConverterLayout.createSequentialGroup()
                .addGroup(tabBaseConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(tabBaseConverterLayout.createSequentialGroup()
                        .addGap(6, 6, 6)
                        .addComponent(lblHex)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addGroup(tabBaseConverterLayout.createSequentialGroup()
                        .addContainerGap()
                        .addGroup(tabBaseConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(lblDec)
                            .addComponent(lblOct)
                            .addComponent(lblBin)
                            .addComponent(lblRadix32))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(tabBaseConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(txtBin, javax.swing.GroupLayout.DEFAULT_SIZE, 1517, Short.MAX_VALUE)
                            .addComponent(txtOct)
                            .addComponent(txtDec)
                            .addComponent(txtHex)
                            .addComponent(txtRadix32))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)))
                .addGroup(tabBaseConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(tabBaseConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(tabBaseConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(tabBaseConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                .addComponent(btnBinCopy)
                                .addComponent(btnOctCopy, javax.swing.GroupLayout.Alignment.TRAILING))
                            .addComponent(btnDecCopy, javax.swing.GroupLayout.Alignment.TRAILING))
                        .addComponent(btnHexCopy, javax.swing.GroupLayout.Alignment.TRAILING))
                    .addComponent(btnRadix32Copy, javax.swing.GroupLayout.Alignment.TRAILING))
                .addContainerGap())
        );
        tabBaseConverterLayout.setVerticalGroup(
            tabBaseConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(tabBaseConverterLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(tabBaseConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblBin)
                    .addComponent(txtBin, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(btnBinCopy))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(tabBaseConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblOct)
                    .addComponent(txtOct, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(btnOctCopy))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(tabBaseConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblDec)
                    .addComponent(txtDec, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(btnDecCopy))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(tabBaseConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblHex)
                    .addComponent(txtHex, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(btnHexCopy))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(tabBaseConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(txtRadix32, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(lblRadix32)
                    .addComponent(btnRadix32Copy))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        tabbetConverter.addTab("Base", tabBaseConverter);

        lblDotDeclIP.setText("Dotted Decimal IP:");

        pnlDotDecIP.setLayout(new java.awt.GridLayout(1, 5, 2, 0));

        txtDec1.setText("192");
        pnlDotDecIP.add(txtDec1);

        txtDec2.setText("168");
        pnlDotDecIP.add(txtDec2);

        txtDec3.setText("1");
        txtDec3.setPreferredSize(new java.awt.Dimension(40, 22));
        pnlDotDecIP.add(txtDec3);

        txtDec4.setText("2");
        pnlDotDecIP.add(txtDec4);

        btnDecIPPaste.setText("Paste");
        btnDecIPPaste.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnDecIPPasteActionPerformed(evt);
            }
        });
        pnlDotDecIP.add(btnDecIPPaste);

        btnDecIPConvert.setText("Convert");
        btnDecIPConvert.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnDecIPConvertActionPerformed(evt);
            }
        });

        lblDotOctCIP.setText("Dotted Octal  C IP:");

        txtDotOctCIP.setEditable(false);

        btnDotOctCIP.setText("Copy");
        btnDotOctCIP.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnDotOctCIPActionPerformed(evt);
            }
        });

        btnOctIP.setText("Copy");
        btnOctIP.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnOctIPActionPerformed(evt);
            }
        });

        txtOctIP.setEditable(false);

        lblOctIP.setText("Octal IP:");

        lblHexIP.setText("Hex IP:");

        txtHexIP.setEditable(false);

        btnHexIP.setText("Copy");
        btnHexIP.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnHexIPActionPerformed(evt);
            }
        });

        lblDotHexCIP.setText("Dotted Hex C IP:");

        txtDotHexCIP.setEditable(false);

        btnDotHexCIP.setText("Copy");
        btnDotHexCIP.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnDotHexCIPActionPerformed(evt);
            }
        });

        lblIntIP.setText("Integer IP:");

        txtIntIP.setEditable(false);

        btnIntIP.setText("Copy");
        btnIntIP.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnIntIPActionPerformed(evt);
            }
        });

        lblIPValid.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        lblIPValid.setToolTipText("");

        lblDotHexBIP.setText("Dotted Hex B IP:");

        txtDotHexBIP.setEditable(false);

        btnDotHexBIP.setText("Copy");
        btnDotHexBIP.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnDotHexBIPActionPerformed(evt);
            }
        });

        lblDotHexAIP.setText("Dotted A Hex IP:");

        txtDotHexAIP.setEditable(false);

        btnDotHexAIP.setText("Copy");
        btnDotHexAIP.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnDotHexAIPActionPerformed(evt);
            }
        });

        lblDotDectBIP.setText("DottedDecimal B IP:");

        txtDotDecBIP.setEditable(false);
        txtDotDecBIP.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                txtDotDecBIPActionPerformed(evt);
            }
        });

        btnDotDecBIP.setText("Copy");
        btnDotDecBIP.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnDotDecBIPActionPerformed(evt);
            }
        });

        txtDotDecAIP.setEditable(false);

        btnDotDecAIP.setText("Copy");
        btnDotDecAIP.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnDotDecAIPActionPerformed(evt);
            }
        });

        lblIPv4MappedIPv6.setText("IPv4 Mapped IPv6:");

        txtIPv4MappedIPv6.setEditable(false);

        btnDotAHexIP1.setText("Copy");
        btnDotAHexIP1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnDotAHexIP1ActionPerformed(evt);
            }
        });

        lblIPv4toUnicode.setText("IPv4 to Unicode:");

        txtIPv4ToUnicode.setEditable(false);

        btnIPv4ToUnicode.setText("Copy");
        btnIPv4ToUnicode.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnIPv4ToUnicodeActionPerformed(evt);
            }
        });

        lblDotOcBtIP.setText("Dotted  Octal B IP:");

        txtDotOctBIP.setEditable(false);
        txtDotOctBIP.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                txtDotOctBIPActionPerformed(evt);
            }
        });

        btnDotBOctIP.setText("Copy");
        btnDotBOctIP.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnDotBOctIPActionPerformed(evt);
            }
        });

        lblDotOctAIP.setText("Dotted Octal A IP:");

        btnDotOctAIP.setText("Copy");
        btnDotOctAIP.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnDotOctAIPActionPerformed(evt);
            }
        });

        txtDotOctAIP.setEditable(false);

        lblTailDotDecCIP.setText("DottedDecimal C IP:");

        txtDotTailDecCIP.setEditable(false);

        btnDotTailDecCIP.setText("Copy");
        btnDotTailDecCIP.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnDotTailDecCIPActionPerformed(evt);
            }
        });

        lblDotDectAIP.setText("DottedDecimal A IP:");

        javax.swing.GroupLayout tabIPFormatConverterLayout = new javax.swing.GroupLayout(tabIPFormatConverter);
        tabIPFormatConverter.setLayout(tabIPFormatConverterLayout);
        tabIPFormatConverterLayout.setHorizontalGroup(
            tabIPFormatConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(tabIPFormatConverterLayout.createSequentialGroup()
                .addGroup(tabIPFormatConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(tabIPFormatConverterLayout.createSequentialGroup()
                        .addGap(6, 6, 6)
                        .addGroup(tabIPFormatConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(lblDotOctCIP)
                            .addComponent(lblDotOcBtIP)
                            .addComponent(lblDotOctAIP)
                            .addComponent(lblOctIP)
                            .addComponent(lblDotHexCIP)
                            .addComponent(lblDotHexBIP)
                            .addComponent(lblDotHexAIP)
                            .addComponent(lblHexIP)
                            .addComponent(lblIPv4MappedIPv6)
                            .addComponent(lblIPv4toUnicode)
                            .addComponent(lblTailDotDecCIP)
                            .addComponent(lblDotDeclIP)
                            .addComponent(lblIntIP)
                            .addComponent(lblDotDectBIP)))
                    .addGroup(tabIPFormatConverterLayout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(lblDotDectAIP)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(tabIPFormatConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(tabIPFormatConverterLayout.createSequentialGroup()
                        .addGroup(tabIPFormatConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(txtDotOctBIP, javax.swing.GroupLayout.DEFAULT_SIZE, 1358, Short.MAX_VALUE)
                            .addComponent(txtDotHexAIP)
                            .addComponent(txtDotTailDecCIP)
                            .addComponent(txtHexIP)
                            .addComponent(txtDotHexCIP)
                            .addComponent(txtDotOctCIP)
                            .addComponent(txtIntIP)
                            .addComponent(txtIPv4ToUnicode)
                            .addComponent(txtIPv4MappedIPv6)
                            .addComponent(txtDotOctAIP)
                            .addComponent(txtOctIP)
                            .addComponent(txtDotDecAIP)
                            .addComponent(txtDotHexBIP)
                            .addComponent(txtDotDecBIP, javax.swing.GroupLayout.Alignment.TRAILING))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(tabIPFormatConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(btnDotDecAIP, javax.swing.GroupLayout.PREFERRED_SIZE, 94, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(btnDotTailDecCIP, javax.swing.GroupLayout.PREFERRED_SIZE, 94, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(btnDotOctCIP, javax.swing.GroupLayout.PREFERRED_SIZE, 94, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(btnDotBOctIP, javax.swing.GroupLayout.PREFERRED_SIZE, 94, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(btnDotOctAIP, javax.swing.GroupLayout.PREFERRED_SIZE, 94, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(btnOctIP, javax.swing.GroupLayout.PREFERRED_SIZE, 94, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(btnDotHexCIP, javax.swing.GroupLayout.PREFERRED_SIZE, 94, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(btnDotHexBIP, javax.swing.GroupLayout.PREFERRED_SIZE, 94, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(btnDotHexAIP, javax.swing.GroupLayout.PREFERRED_SIZE, 94, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(btnHexIP, javax.swing.GroupLayout.PREFERRED_SIZE, 94, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(btnDotAHexIP1, javax.swing.GroupLayout.PREFERRED_SIZE, 94, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(btnIPv4ToUnicode, javax.swing.GroupLayout.PREFERRED_SIZE, 94, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(btnDotDecBIP, javax.swing.GroupLayout.PREFERRED_SIZE, 94, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(btnIntIP, javax.swing.GroupLayout.PREFERRED_SIZE, 94, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(82, 82, 82))
                    .addGroup(tabIPFormatConverterLayout.createSequentialGroup()
                        .addComponent(pnlDotDecIP, javax.swing.GroupLayout.PREFERRED_SIZE, 467, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnDecIPConvert)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(lblIPValid, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                .addGap(0, 0, 0))
        );
        tabIPFormatConverterLayout.setVerticalGroup(
            tabIPFormatConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(tabIPFormatConverterLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(tabIPFormatConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(tabIPFormatConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                        .addComponent(lblIPValid, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(lblDotDeclIP)
                        .addComponent(pnlDotDecIP, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addComponent(btnDecIPConvert))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(tabIPFormatConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(tabIPFormatConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(txtDotDecBIP, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(lblDotDectBIP))
                    .addComponent(btnDotDecBIP))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(tabIPFormatConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(tabIPFormatConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(txtDotDecAIP, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(btnDotDecAIP))
                    .addComponent(lblDotDectAIP))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(tabIPFormatConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblIntIP)
                    .addComponent(txtIntIP, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(btnIntIP))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(tabIPFormatConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblTailDotDecCIP)
                    .addComponent(txtDotTailDecCIP, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(btnDotTailDecCIP))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(tabIPFormatConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(btnDotOctCIP)
                    .addComponent(lblDotOctCIP)
                    .addComponent(txtDotOctCIP, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(tabIPFormatConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblDotOcBtIP)
                    .addComponent(btnDotBOctIP)
                    .addComponent(txtDotOctBIP, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(tabIPFormatConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblDotOctAIP)
                    .addComponent(btnDotOctAIP)
                    .addComponent(txtDotOctAIP, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(tabIPFormatConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(btnOctIP)
                    .addComponent(lblOctIP)
                    .addComponent(txtOctIP, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(tabIPFormatConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblDotHexCIP)
                    .addComponent(txtDotHexCIP, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(btnDotHexCIP))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(tabIPFormatConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(txtDotHexBIP, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(lblDotHexBIP)
                    .addComponent(btnDotHexBIP))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(tabIPFormatConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(txtDotHexAIP, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(lblDotHexAIP)
                    .addComponent(btnDotHexAIP))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(tabIPFormatConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblHexIP)
                    .addComponent(txtHexIP, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(btnHexIP))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(tabIPFormatConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(txtIPv4MappedIPv6, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(btnDotAHexIP1)
                    .addComponent(lblIPv4MappedIPv6))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(tabIPFormatConverterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblIPv4toUnicode)
                    .addComponent(txtIPv4ToUnicode, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(btnIPv4ToUnicode))
                .addGap(615, 615, 615))
        );

        tabbetConverter.addTab("IP Format", tabIPFormatConverter);

        tabbetTranscoder.addTab("Converter", tabbetConverter);

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

    private final HexViewTab hexInputViewTab = new HexViewTab();
    private final HexViewTab hexOutputViewTab = new HexViewTab();

    private final javax.swing.JPanel pnlOutputFormat = new javax.swing.JPanel();

    /*
     * ステータスメッセージ書式
     */
    private static final MessageFormat STATUS_TEXT_FORMAT = new MessageFormat(
            "Length:{0,number} Position:{1,number} SelectLength:{2,number}"); // @jve:decl-index=0:

    private void txtNumFormatKeyPressed(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_txtNumFormatKeyPressed
        //this.lblExampleValue.setText(String.format(this.txtFormat.getText(), 123));
    }//GEN-LAST:event_txtNumFormatKeyPressed

    private void rdoAlphaNumActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rdoAlphaNumActionPerformed
        firePropertyChange(JTransCoderProperty.JTRANS_CODER_PROPERTY, null, this.getProperty());
    }//GEN-LAST:event_rdoAlphaNumActionPerformed

    private void btnSmartDecodeActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnSmartDecodeActionPerformed
        this.toSmartDecode(this.getInputText());
    }//GEN-LAST:event_btnSmartDecodeActionPerformed

    private void btnEncodeActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnEncodeActionPerformed
        try {
            String value = this.getInputText();
            String encode = value;
            boolean metaChar = this.chkMetaChar.isSelected();
            if (this.rdoUrl.isSelected()) {
                encode = SmartCodec.toUrlEncode(value, this.getSelectEncode(), TransUtil.getEncodeTypePattern(this.getEncodeType()), this.rdoUpperCase.isSelected());
            } else if (this.rdoUrlUnicode.isSelected()) {
                encode = SmartCodec.toUnocodeUrlEncode(value, TransUtil.getEncodeTypePattern(this.getEncodeType()), this.rdoUpperCase.isSelected());
                if (this.rdoUpperCase.isSelected()) {
                    encode = encode.toUpperCase();
                }
            } else if (this.rdoBase64.isSelected()) {
                encode = CodecUtil.toBase64Encode(value, this.getSelectEncode(), this.chkPadding.isSelected());
                if (this.chk76Newline.isSelected()) {
                    if (!this.chkRawMode.isSelected()) {
                        encode = TransUtil.newLine(TransUtil.getNewLine(this.getSelectNewLine()), encode, 76);
//                        encode = CodecUtil.toBase64Encode(value, this.getSelectEncode(), this.chkPadding.isSelected(), 76, TransUtil.getNewLine(this.getSelectNewLine()));
                    }
                } else if (this.chk64Newline.isSelected()) {
                    if (!this.chkRawMode.isSelected()) {
                        encode = TransUtil.newLine(TransUtil.getNewLine(this.getSelectNewLine()), encode, 64);
//                        encode = CodecUtil.toBase64Encode(value, this.getSelectEncode(), this.chkPadding.isSelected(), 64, TransUtil.getNewLine(this.getSelectNewLine()));
                    }
                }
            } else if (this.rdoBase64URLSafe.isSelected()) {
                encode = CodecUtil.toBase64URLSafeEncode(value, this.getSelectEncode());
            } else if (this.rdoBase64andURL.isSelected()) {
                encode = SmartCodec.toUrlEncode(CodecUtil.toBase64Encode(value, this.getSelectEncode()), StandardCharsets.US_ASCII, TransUtil.getEncodeTypePattern(this.getEncodeType()), this.rdoUpperCase.isSelected());
            } else if (this.rdoBase32.isSelected()) {
                encode = CodecUtil.toBase32Encode(value, this.getSelectEncode(), this.chkNPadding.isSelected());
            } else if (this.rdoBase16.isSelected()) {
                encode = CodecUtil.toBase16Encode(value, this.getSelectEncode(), this.chkNPadding.isSelected());
//            } else if (this.rdoUuencode.isSelected()) {
//                encode = TransUtil.toUuencode(value, this.getSelectEncode());
            } else if (this.rdoQuotedPrintable.isSelected()) {
                encode = TransUtil.toQuotedPrintable(value, this.getSelectEncode());
            } else if (this.rdoPunycode.isSelected()) {
                encode = ConvertUtil.toPunycodeEncode(value);
            } else if (this.rdoHtml.isSelected()) {
                encode = HttpUtil.toHtmlEncode(value);
            } else if (this.rdoUnicodeHex.isSelected()) {
                encode = SmartCodec.toUnocodeEncode(value, TransUtil.getEncodeTypePattern(this.getEncodeType()), this.rdoUpperCase.isSelected());
            } else if (this.rdoUnicodeHex2.isSelected()) {
                encode = SmartCodec.toUnocodeEncode(value, "$", TransUtil.getEncodeTypePattern(this.getEncodeType()), this.rdoUpperCase.isSelected());
            } else if (this.rdoByteNoneHex.isSelected()) {
                encode = TransUtil.toByteHexEncode(value, this.getSelectEncode(), this.rdoUpperCase.isSelected());
            } else if (this.rdoByteXHex.isSelected()) {
                encode = TransUtil.toByteHex1Encode(value, this.getSelectEncode(), TransUtil.getEncodeTypePattern(this.getEncodeType()), this.rdoUpperCase.isSelected());
            } else if (this.rdoByteHex2.isSelected()) {
                encode = TransUtil.toByteHex2Encode(value, this.getSelectEncode(), TransUtil.getEncodeTypePattern(this.getEncodeType()), this.rdoUpperCase.isSelected());
            } else if (this.rdoByteOct.isSelected()) {
                encode = TransUtil.toByteOctEncode(value, this.getSelectEncode(), TransUtil.getEncodeTypePattern(this.getEncodeType()));
            } else if (this.rdoHtmlDec.isSelected()) {
                encode = SmartCodec.toHtmlDecEncode(value, TransUtil.getEncodeTypePattern(this.getEncodeType()));
            } else if (this.rdoHtmlUnicode.isSelected()) {
                encode = SmartCodec.toHtmlUnicodeEncode(value, TransUtil.getEncodeTypePattern(this.getEncodeType()), this.rdoUpperCase.isSelected());
            } else if (this.rdoHtmlByteHex.isSelected()) {
                encode = SmartCodec.toHtmlByteHexEncode(value, this.getSelectEncode(), TransUtil.getEncodeTypePattern(this.getEncodeType()), this.rdoUpperCase.isSelected());
            } else if (this.rdoGzip.isSelected()) {
                encode = StringUtil.getBytesRawString(ConvertUtil.compressGzip(StringUtil.getBytesCharset(value, this.getSelectEncode())));
            } else if (this.rdoZLIB.isSelected()) {
                encode = StringUtil.getBytesRawString(ConvertUtil.compressZlib(StringUtil.getBytesCharset(value, this.getSelectEncode())));
            } else if (this.rdoZLIB_NOWRAP.isSelected()) {
                encode = StringUtil.getBytesRawString(ConvertUtil.compressZlib(StringUtil.getBytesCharset(value, this.getSelectEncode()), true));
            } else if (this.rdoUTF7.isSelected()) {
                encode = TransUtil.toUTF7Encode(value);
            } else if (this.rdoILLUTF8.isSelected()) {
                String byteUTF8 = (String) this.cmbIILUTF8.getSelectedItem();
                byte[] out_byte = TransUtil.UTF8Encode(value, ConvertUtil.parseIntDefault(byteUTF8, 2));
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
                encode = ConvertUtil.encodeCLangQuote(encode, metaChar);
            } else if (this.rdoJSON.isSelected()) {
                encode = ConvertUtil.encodeJsonLiteral(encode, metaChar);
            } else if (this.rdoSQLLang.isSelected()) {
                encode = ConvertUtil.encodeSQLLangQuote(encode, metaChar);
            } else if (this.rdoRegex.isSelected()) {
                encode = ConvertUtil.toRegexEncode(encode, metaChar);
            }
            this.setOutput(encode);
        } catch (IOException | DecoderException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
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
        } else if (this.rdoBase64andURL.isSelected()) {
            encodePattern = TransUtil.EncodePattern.BASE64_AND_URL;
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
        } else if (this.rdoUnicodeHex2.isSelected()) {
            encodePattern = TransUtil.EncodePattern.UNICODE2;
        } else if (this.rdoByteNoneHex.isSelected()) {
            encodePattern = TransUtil.EncodePattern.BYTE_HEX;
        } else if (this.rdoByteXHex.isSelected()) {
            encodePattern = TransUtil.EncodePattern.BYTE_HEX1;
        } else if (this.rdoByteHex2.isSelected()) {
            encodePattern = TransUtil.EncodePattern.BYTE_HEX2;
        } else if (this.rdoByteOct.isSelected()) {
            encodePattern = TransUtil.EncodePattern.BYTE_OCT;
        } else if (this.rdoHtmlDec.isSelected()) {
            encodePattern = TransUtil.EncodePattern.HTML;
        } else if (this.rdoHtmlByteHex.isSelected()) {
            encodePattern = TransUtil.EncodePattern.HTML_BYTE;
        } else if (this.rdoHtmlUnicode.isSelected()) {
            encodePattern = TransUtil.EncodePattern.HTML_UNICODE;
        } else if (this.rdoGzip.isSelected()) {
            encodePattern = TransUtil.EncodePattern.GZIP;
        } else if (this.rdoZLIB.isSelected()) {
            encodePattern = TransUtil.EncodePattern.ZLIB;
        } else if (this.rdoZLIB_NOWRAP.isSelected()) {
            encodePattern = TransUtil.EncodePattern.ZLIB_NOWRAP;
        } else if (this.rdoUTF7.isSelected()) {
            encodePattern = TransUtil.EncodePattern.UTF7;
        } else if (this.rdoILLUTF8.isSelected()) {
            encodePattern = TransUtil.EncodePattern.UTF8_ILL;
        } else if (this.rdoCLang.isSelected()) {
            encodePattern = TransUtil.EncodePattern.C_LANG;
        } else if (this.rdoJSON.isSelected()) {
            encodePattern = TransUtil.EncodePattern.JSON;
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
            String inputText = BouncyUtil.toMD2Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashMd2ActionPerformed

    private void btnHashMd5ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashMd5ActionPerformed
        try {
            String inputText = BouncyUtil.toMD5Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashMd5ActionPerformed

    private void btnHashSha1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashSha1ActionPerformed
        try {
            String inputText = BouncyUtil.toSHA1Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashSha1ActionPerformed

    private void btnHashSha224ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashSha224ActionPerformed
        try {
            String inputText = BouncyUtil.toSHA224Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashSha224ActionPerformed

    private void btnHashSha384ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashSha384ActionPerformed
        try {
            String inputText = BouncyUtil.toSHA384Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashSha384ActionPerformed

    private void btnHashSha512ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashSha512ActionPerformed
        try {
            String inputText = BouncyUtil.toSHA512Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashSha512ActionPerformed

    private void rdoCRLFActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rdoCRLFActionPerformed
        firePropertyChange(JTransCoderProperty.JTRANS_CODER_PROPERTY, null, this.getProperty());
    }//GEN-LAST:event_rdoCRLFActionPerformed

    private void btnOutputfileActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnOutputfileActionPerformed
        JFileChooser filechooser = new JFileChooser();
        filechooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        int selected = filechooser.showSaveDialog(this);
        if (selected == JFileChooser.APPROVE_OPTION) {
            try {
                File file = filechooser.getSelectedFile();
                byte[] output = this.getOutputByte();
                FileUtil.bytesToFile(output, file);
            } catch (IOException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
    }//GEN-LAST:event_btnOutputfileActionPerformed

    private void rdoLigthActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rdoLigthActionPerformed
        firePropertyChange(JTransCoderProperty.JTRANS_CODER_PROPERTY, null, this.getProperty());
    }//GEN-LAST:event_rdoLigthActionPerformed

    private void btnOutputToInputActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnOutputToInputActionPerformed
        String outputText = this.getOutputText();
        byte[] outputByte = this.getOutputByte();
        this.clearText();
        this.setInputText(outputText);
        this.setInputByte(outputByte);
    }//GEN-LAST:event_btnOutputToInputActionPerformed

    private void rdoURLSafeActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rdoURLSafeActionPerformed
        firePropertyChange(JTransCoderProperty.JTRANS_CODER_PROPERTY, null, this.getProperty());
    }//GEN-LAST:event_rdoURLSafeActionPerformed

    private void rdoLowerCaseActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rdoLowerCaseActionPerformed
        firePropertyChange(JTransCoderProperty.JTRANS_CODER_PROPERTY, null, this.getProperty());
    }//GEN-LAST:event_rdoLowerCaseActionPerformed

    private void btnCalcActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnCalcActionPerformed
        int base = ConvertUtil.parseIntDefault(this.txtBase.getText(), 0);
        int exponent = ConvertUtil.parseIntDefault(this.txtExponent.getText(), 0);
        this.txtStrength.setText(String.format("%4.2f", ConvertUtil.calcStlength(base, exponent)));
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
        this.txtBase.setText(StringUtil.toString(map.toArray().length));
        this.txtExponent.setText(StringUtil.toString(sum_len / tokenList.length));
        this.btnCalcActionPerformed(evt);
    }//GEN-LAST:event_btnAnalyzeActionPerformed

    private void btnInputfileActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnInputfileActionPerformed
        JFileChooser filechooser = new JFileChooser();
        filechooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        int selected = filechooser.showOpenDialog(this);
        if (selected == JFileChooser.APPROVE_OPTION) {
            try {
                File file = filechooser.getSelectedFile();
                byte[] input = FileUtil.bytesFromFile(file);
                this.setInputText(StringUtil.getBytesRawString(input));
                this.setInputByte(input);
            } catch (IOException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
    }//GEN-LAST:event_btnInputfileActionPerformed

    private void tabbetInputStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_tabbetInputStateChanged
        if (this.txtInputRaw == null) {
            return;
        }
        if (this.chkRawMode.isSelected()) {
            this.setInputByte(StringUtil.getBytesRaw(this.txtInputRaw.getText()));
        } else {
            this.setInputByte(StringUtil.getBytesRaw(TransUtil.replaceNewLine(getSelectNewLine(), this.txtInputRaw.getText())));
        }
    }//GEN-LAST:event_tabbetInputStateChanged

    private void btnClearActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnClearActionPerformed
        this.clearText();
    }//GEN-LAST:event_btnClearActionPerformed

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
        firePropertyChange(JTransCoderProperty.JTRANS_CODER_PROPERTY, null, this.getProperty());
    }//GEN-LAST:event_rdoAllActionPerformed

    private void rdoUpperCaseActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rdoUpperCaseActionPerformed
        firePropertyChange(JTransCoderProperty.JTRANS_CODER_PROPERTY, null, this.getProperty());
    }//GEN-LAST:event_rdoUpperCaseActionPerformed

    private void rdoNoneActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rdoNoneActionPerformed
        firePropertyChange(JTransCoderProperty.JTRANS_CODER_PROPERTY, null, this.getProperty());
    }//GEN-LAST:event_rdoNoneActionPerformed

    private void rdoCRActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rdoCRActionPerformed
        firePropertyChange(JTransCoderProperty.JTRANS_CODER_PROPERTY, null, this.getProperty());
    }//GEN-LAST:event_rdoCRActionPerformed

    private void rdoLFActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rdoLFActionPerformed
        firePropertyChange(JTransCoderProperty.JTRANS_CODER_PROPERTY, null, this.getProperty());
    }//GEN-LAST:event_rdoLFActionPerformed

    private void chkViewLineWrapActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_chkViewLineWrapActionPerformed
        this.txtInputRaw.setLineWrap(this.chkViewLineWrap.isSelected());
        this.txtInputRaw.setWrapStyleWord(false);
        this.txtOutputRaw.setLineWrap(this.chkViewLineWrap.isSelected());
        this.txtOutputRaw.setWrapStyleWord(false);
        if (evt != null) {
            firePropertyChange(JTransCoderProperty.JTRANS_CODER_PROPERTY, null, this.getProperty());
        }
    }//GEN-LAST:event_chkViewLineWrapActionPerformed

    private void chkRawModeActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_chkRawModeActionPerformed
        this.cmbEncoding.setEnabled(!(this.chkRawMode.isSelected() || this.chkGuess.isSelected()));
        SwingUtil.setContainerEnable(this.pnlNewLine, !this.chkRawMode.isSelected());
        if (evt != null) {
            firePropertyChange(JTransCoderProperty.JTRANS_CODER_PROPERTY, null, this.getProperty());
        }
    }//GEN-LAST:event_chkRawModeActionPerformed

    private void chkGuessActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_chkGuessActionPerformed
        this.chkRawMode.setEnabled(!this.chkGuess.isSelected());
        this.cmbEncoding.setEnabled(!(this.chkRawMode.isSelected() || this.chkGuess.isSelected()));
        if (evt != null) {
            firePropertyChange(JTransCoderProperty.JTRANS_CODER_PROPERTY, null, this.getProperty());
        }
    }//GEN-LAST:event_chkGuessActionPerformed

    private void cmbEncodingActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cmbEncodingActionPerformed
        firePropertyChange(JTransCoderProperty.JTRANS_CODER_PROPERTY, null, this.getProperty());
    }//GEN-LAST:event_cmbEncodingActionPerformed

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
                            return TransUtil.join(System.lineSeparator(), list);
                        }

                        @Override
                        protected void process(List<Object> chunks) {
                        }

                        @Override
                        protected void done() {
                            try {
                                txtGenarate.setText(get());
                            } catch (InterruptedException | ExecutionException ex) {
                                logger.log(Level.SEVERE, ex.getMessage(), ex);
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
                    final Date dateStart = getGeneraterDateStart();
                    final Date dateEnd = getGeneraterDateEnd();
                    final LocalDate localDateStart = dateStart.toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
                    final LocalDate localDateLocalEnd = dateEnd.toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
                    final int stepNum = (Integer) this.spnDateStep.getModel().getValue();
                    final String dateUnit = (String) this.cmbDateUnit.getSelectedItem();

                    SwingWorker swList = new SwingWorker<String, Object>() {
                        @Override
                        protected String doInBackground() throws Exception {
                            DateUnit unit = Enum.valueOf(DateUnit.class, dateUnit);
                            String[] list = TransUtil.dateList(numFormat, localDateStart, localDateLocalEnd, stepNum, unit);
                            return TransUtil.join(System.lineSeparator(), list);
                        }

                        @Override
                        protected void process(List<Object> chunks) {
                        }

                        @Override
                        protected void done() {
                            try {
                                txtGenarate.setText(get());
                            } catch (InterruptedException | ExecutionException ex) {
                                logger.log(Level.SEVERE, ex.getMessage(), ex);
                            }
                        }
                    };
                    swList.execute();
                } catch (IllegalFormatException ex) {
                    JOptionPane.showMessageDialog(this, BUNDLE.getString("view.transcoder.format.error"), "JTranscoder", JOptionPane.INFORMATION_MESSAGE);
                } catch (IllegalArgumentException ex) {
                    JOptionPane.showMessageDialog(this, ex.getMessage(), "JTranscoder", JOptionPane.INFORMATION_MESSAGE);
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
                        return TransUtil.join(System.lineSeparator(), list);
                    }

                    protected void process(List<Object> chunks) {
                    }

                    protected void done() {
                        try {
                            txtGenarate.setText(get());
                        } catch (InterruptedException | ExecutionException ex) {
                            logger.log(Level.SEVERE, ex.getMessage(), ex);
                        }
                    }
                };
                swList.execute();
            }
        } else if (this.tabbetGenerate.getSelectedIndex() == this.tabbetGenerate.indexOfTab("GenerateKeyPair")) {
            try {
                txtGenarate.setText(exportKeyPairToPem());
            }
            catch (UnsupportedOperationException ex) {
                JOptionPane.showMessageDialog(this, ex.getMessage(), "JTranscoder", JOptionPane.INFORMATION_MESSAGE);
            }
        }
    }//GEN-LAST:event_btnGenerateActionPerformed

    private void btnGeneCopyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnGeneCopyActionPerformed
        String s = this.txtGenarate.getText();
        SwingUtil.systemClipboardCopy(s);
    }//GEN-LAST:event_btnGeneCopyActionPerformed

    private void btnGeneSavetoFileActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnGeneSavetoFileActionPerformed
        String s = this.txtGenarate.getText();
        JFileChooser filechooser = new JFileChooser();
        filechooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        int selected = filechooser.showSaveDialog(null);
        if (selected == JFileChooser.APPROVE_OPTION) {
            File file = filechooser.getSelectedFile();
            if (SwingUtil.isFileOverwriteConfirmed(file, String.format(BUNDLE.getString("extend.exists.overwrite.message"), file.getName()), BUNDLE.getString("extend.exists.overwrite.confirm"))) {
                try (BufferedOutputStream fstm = new BufferedOutputStream(new FileOutputStream(file))) {
                    fstm.write(StringUtil.getBytesCharset(s, this.getSelectEncode()));
                } catch (Exception ex) {
                    logger.log(Level.SEVERE, ex.getMessage(), ex);
                }
            }
        }
    }//GEN-LAST:event_btnGeneSavetoFileActionPerformed

    private void btnSmartMatchActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnSmartMatchActionPerformed
        try {
            String enc = (this.chkWithByte.isSelected()) ? this.getSelectEncode() : null;
            String inputText = MatchUtil.toSmartMatch(getInputText(), enc);
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnSmartMatchActionPerformed

    private void btnOutputCopyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnOutputCopyActionPerformed
        SwingUtil.systemClipboardCopy(this.txtOutputRaw.getText());
    }//GEN-LAST:event_btnOutputCopyActionPerformed

    private void btnCRC32ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnCRC32ActionPerformed
        try {
            String inputText = Long.toString(HashUtil.toCRC32Sum(getInputText(), this.getSelectEncode()));
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnCRC32ActionPerformed

    private void btnAdler32ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnAdler32ActionPerformed
        try {
            String inputText = Long.toString(HashUtil.toAdler32Sum(getInputText(), this.getSelectEncode()));
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnAdler32ActionPerformed

    private void rdoRegexStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_rdoRegexStateChanged
        this.doStateDecodeChange();
    }//GEN-LAST:event_rdoRegexStateChanged

    private void btnSmartFormatActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnSmartFormatActionPerformed
        this.toSmartDecode(this.getInputText(), TransUtil.EncodePattern.NONE);
    }//GEN-LAST:event_btnSmartFormatActionPerformed

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

    private void btnMurmurHash2_32ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnMurmurHash2_32ActionPerformed
        try {
            String inputText = Long.toString(CodecUtil.toMurmurHash2_32(getInputText(), this.getSelectEncode()));
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnMurmurHash2_32ActionPerformed

    private void btnMurmurHash2_64ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnMurmurHash2_64ActionPerformed
        try {
            String inputText = Long.toString(CodecUtil.toMurmurHash2_64(getInputText(), this.getSelectEncode()));
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnMurmurHash2_64ActionPerformed

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

    private void btnUnixtimeCopyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnUnixtimeCopyActionPerformed
        SwingUtil.systemClipboardCopy(this.txtUnixtime.getText());
    }//GEN-LAST:event_btnUnixtimeCopyActionPerformed

    private void btnJavaSerialCopyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnJavaSerialCopyActionPerformed
        SwingUtil.systemClipboardCopy(this.txtJavaSerial.getText());
    }//GEN-LAST:event_btnJavaSerialCopyActionPerformed

    private void btnExcelSerialActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnExcelSerialActionPerformed
        SwingUtil.systemClipboardCopy(this.txtExcelSerial.getText());
    }//GEN-LAST:event_btnExcelSerialActionPerformed

    private void cmbTimezoneItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_cmbTimezoneItemStateChanged
//        Date date = this.getConverterDateTime();
//        this.setSystemZoneDate(date.toInstant());
        this.updateZoneDateTime();
    }//GEN-LAST:event_cmbTimezoneItemStateChanged

    private void setSystemZoneDate(Instant instant) {
        ZonedDateTime zdtm = ZonedDateTime.ofInstant(instant, ZoneOffset.UTC);
        this.txtSystemZoneDateGMT.setText(SYSTEM_ZONE_DATE_FORMATTER.withZone(ZoneOffset.UTC).format(zdtm));
        this.txtSystemZoneDate.setText(SYSTEM_ZONE_DATE_FORMATTER.withZone(ZoneId.systemDefault()).format(zdtm));
    }

    private void setSystemZoneDate(ZonedDateTime zdtm) {
        this.txtSystemZoneDateGMT.setText(SYSTEM_ZONE_DATE_FORMATTER.withZone(ZoneOffset.UTC).format(zdtm));
        this.txtSystemZoneDate.setText(SYSTEM_ZONE_DATE_FORMATTER.withZone(ZoneId.systemDefault()).format(zdtm));
    }

    private void txtUnixtimeFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_txtUnixtimeFocusLost
        try {
            this.txtUnixtime.commitEdit();
            long unix_value = (long) this.txtUnixtime.getValue();
            long java_value = unix_value * 1000L;
            BigDecimal excel_serial = TransUtil.toExcelSerial(unix_value);

            this.txtJavaSerial.setValue(java_value);
            // Excel Serial = 25569 + ((Unixtime + (60 * 60 * 9)) / (60 * 60 * 24))
            this.txtExcelSerial.setValue(excel_serial.doubleValue());

            ZonedDateTime zdtm = ZonedDateTime.ofInstant(Instant.ofEpochMilli(java_value), ZoneId.systemDefault());
            this.setSystemZoneDate(zdtm.toInstant());
            this.setConverterZoneDateTime(java_value);

        } catch (ParseException ex) {
            logger.log(Level.INFO, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_txtUnixtimeFocusLost

    private void txtJavaSerialFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_txtJavaSerialFocusLost
        try {
            this.txtJavaSerial.commitEdit();
            long java_value = (long) this.txtJavaSerial.getValue();
            long unix_value = java_value / 1000L;
            BigDecimal excel_serial = TransUtil.toExcelSerial(unix_value);

            this.txtUnixtime.setValue(unix_value);
            // Excel Serial = 25569 + ((Unixtime + (60 * 60 * 9)) / (60 * 60 * 24))
            this.txtExcelSerial.setValue(excel_serial.doubleValue());

            ZonedDateTime zdtm = ZonedDateTime.ofInstant(Instant.ofEpochMilli(java_value), ZoneId.systemDefault());
            this.setSystemZoneDate(zdtm.toInstant());

            this.setConverterZoneDateTime(java_value);

        } catch (ParseException ex) {
            logger.log(Level.INFO, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_txtJavaSerialFocusLost

    private void txtExcelSerialFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_txtExcelSerialFocusLost
        try {
            this.txtExcelSerial.commitEdit();
            Number excel_serial = (Number) this.txtExcelSerial.getValue();
            long unix_value = TransUtil.toEpochSecond(BigDecimal.valueOf(excel_serial.doubleValue()));
            long java_value = unix_value * 1000L;

            this.txtUnixtime.setValue(unix_value);
            this.txtJavaSerial.setValue(java_value);

            ZonedDateTime zdtm = ZonedDateTime.ofInstant(Instant.ofEpochMilli(java_value), ZoneId.systemDefault());
            this.setSystemZoneDate(zdtm.toInstant());

            this.setConverterZoneDateTime(java_value);

        } catch (ParseException ex) {
            logger.log(Level.INFO, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_txtExcelSerialFocusLost

    private void btnZoneDateCopyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnZoneDateCopyActionPerformed
        SwingUtil.systemClipboardCopy(this.txtSystemZoneDate.getText());
    }//GEN-LAST:event_btnZoneDateCopyActionPerformed

    private void btnHashSha256ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashSha256ActionPerformed
        try {
            String inputText = BouncyUtil.toSHA256Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashSha256ActionPerformed

    private void btnHashSha512_224ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashSha512_224ActionPerformed
        try {
            String inputText = BouncyUtil.toSHA512_224Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashSha512_224ActionPerformed

    private void btnHashSha512_256ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashSha512_256ActionPerformed
        try {
            String inputText = BouncyUtil.toSHA512_256Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashSha512_256ActionPerformed

    private void btnHashSha3_224ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashSha3_224ActionPerformed
        try {
            String inputText = BouncyUtil.toSHA3_224Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashSha3_224ActionPerformed

    private void btnHashSha3_256ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashSha3_256ActionPerformed
        try {
            String inputText = BouncyUtil.toSHA3_256Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashSha3_256ActionPerformed

    private void btnHashSha3_384ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashSha3_384ActionPerformed
        try {
            String inputText = BouncyUtil.toSHA3_384Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashSha3_384ActionPerformed

    private void btnHashSha3_512ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashSha3_512ActionPerformed
        try {
            String inputText = BouncyUtil.toSHA3_512Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashSha3_512ActionPerformed

    private void btnCRC32CActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnCRC32CActionPerformed
        try {
            String inputText = Long.toString(HashUtil.toCRC32CSum(getInputText(), this.getSelectEncode()));
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnCRC32CActionPerformed

    private void btnHashRIPEMD128ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashRIPEMD128ActionPerformed
        try {
            String inputText = BouncyUtil.toRIPEMD128Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashRIPEMD128ActionPerformed

    private void btnHashRIPEMD160ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashRIPEMD160ActionPerformed
        try {
            String inputText = BouncyUtil.toRIPEMD160Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashRIPEMD160ActionPerformed

    private void btnHashRIPEMD256ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashRIPEMD256ActionPerformed
        try {
            String inputText = BouncyUtil.toRIPEMD256Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashRIPEMD256ActionPerformed

    private void btnHashRIPEMD320ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashRIPEMD320ActionPerformed
        try {
            String inputText = BouncyUtil.toRIPEMD320Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashRIPEMD320ActionPerformed

    private void btnHashTigerActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashTigerActionPerformed
        try {
            String inputText = BouncyUtil.toTigerSum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashTigerActionPerformed

    private void btnHashGOST3411ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashGOST3411ActionPerformed
        try {
            String inputText = BouncyUtil.toGOST3411Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashGOST3411ActionPerformed

    private void btnHashWHIRLPOOLActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashWHIRLPOOLActionPerformed
        try {
            String inputText = BouncyUtil.toWHIRLPOOLSum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashWHIRLPOOLActionPerformed

    private void btnHashSHAKE128ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashSHAKE128ActionPerformed
        try {
            String inputText = BouncyUtil.toSHAKE128Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashSHAKE128ActionPerformed

    private void btnHashSHAKE256ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashSHAKE256ActionPerformed
        try {
            String inputText = BouncyUtil.toSHAKE256um(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashSHAKE256ActionPerformed

    private void btnHashSM3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashSM3ActionPerformed
        try {
            String inputText = BouncyUtil.toSM3Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashSM3ActionPerformed

    private void btnHashSKEIN256_128ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashSKEIN256_128ActionPerformed
        try {
            String inputText = BouncyUtil.toSKEIN256_128Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashSKEIN256_128ActionPerformed

    private void btnHashSKEIN256_160ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashSKEIN256_160ActionPerformed
        try {
            String inputText = BouncyUtil.toSKEIN256_160Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashSKEIN256_160ActionPerformed

    private void btnHashSKEIN256_224ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashSKEIN256_224ActionPerformed
        try {
            String inputText = BouncyUtil.toSKEIN256_224Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashSKEIN256_224ActionPerformed

    private void btnHashSKEIN256_256ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashSKEIN256_256ActionPerformed
        try {
            String inputText = BouncyUtil.toSKEIN256_256Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashSKEIN256_256ActionPerformed

    private void btnHashSKEIN512_128ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashSKEIN512_128ActionPerformed
        try {
            String inputText = BouncyUtil.toSKEIN512_128Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashSKEIN512_128ActionPerformed

    private void btnHashSKEIN512_160ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashSKEIN512_160ActionPerformed
        try {
            String inputText = BouncyUtil.toSKEIN512_160Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashSKEIN512_160ActionPerformed

    private void btnHashSKEIN512_224ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashSKEIN512_224ActionPerformed
        try {
            String inputText = BouncyUtil.toSKEIN512_224Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashSKEIN512_224ActionPerformed

    private void btnHashSKEIN512_256ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashSKEIN512_256ActionPerformed
        try {
            String inputText = BouncyUtil.toSKEIN512_256Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashSKEIN512_256ActionPerformed

    private void btnHashSKEIN512_384ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashSKEIN512_384ActionPerformed
        try {
            String inputText = BouncyUtil.toSKEIN512_384Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashSKEIN512_384ActionPerformed

    private void btnHashSKEIN512_512ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashSKEIN512_512ActionPerformed
        try {
            String inputText = BouncyUtil.toSKEIN512_512Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashSKEIN512_512ActionPerformed

    private void btnHashSKEIN1024_384ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashSKEIN1024_384ActionPerformed
        try {
            String inputText = BouncyUtil.toSKEIN1024_384Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashSKEIN1024_384ActionPerformed

    private void btnHashSKEIN1024_512ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashSKEIN1024_512ActionPerformed
        try {
            String inputText = BouncyUtil.toSKEIN1024_512Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashSKEIN1024_512ActionPerformed

    private void btnHashSKEIN1024_1024ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashSKEIN1024_1024ActionPerformed
        try {
            String inputText = BouncyUtil.toSKEIN1024_1024Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashSKEIN1024_1024ActionPerformed

    private void btnHashKECCAK224ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashKECCAK224ActionPerformed
        try {
            String inputText = BouncyUtil.toKECCAK224Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashKECCAK224ActionPerformed

    private void btnHashKECCAK256ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashKECCAK256ActionPerformed
        try {
            String inputText = BouncyUtil.toKECCAK256Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashKECCAK256ActionPerformed

    private void btnHashKECCAK288ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashKECCAK288ActionPerformed
        try {
            String inputText = BouncyUtil.toKECCAK288Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashKECCAK288ActionPerformed

    private void btnHashKECCAK384ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashKECCAK384ActionPerformed
        try {
            String inputText = BouncyUtil.toKECCAK384Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashKECCAK384ActionPerformed

    private void btnHashKECCAK512ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashKECCAK512ActionPerformed
        try {
            String inputText = BouncyUtil.toKECCAK512Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashKECCAK512ActionPerformed

    private void btnHashHARAKA256ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashHARAKA256ActionPerformed
        try {
            String inputText = BouncyUtil.toHARAKA256Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (IllegalStateException | UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashHARAKA256ActionPerformed

    private void btnHashHARAKA512ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashHARAKA512ActionPerformed
        try {
            String inputText = BouncyUtil.toHARAKA512Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (IllegalStateException | UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashHARAKA512ActionPerformed

    private void btnHashGOST3411_2012_256ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashGOST3411_2012_256ActionPerformed
        try {
            String inputText = BouncyUtil.toGOST3411_2012_256Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashGOST3411_2012_256ActionPerformed

    private void btnHashGOST3411_2012_512ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashGOST3411_2012_512ActionPerformed
        try {
            String inputText = BouncyUtil.toGOST3411_2012_512Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashGOST3411_2012_512ActionPerformed

    private void btnHashDSTU7564_256ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashDSTU7564_256ActionPerformed
        try {
            String inputText = BouncyUtil.toDSTU7564_256Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashDSTU7564_256ActionPerformed

    private void btnHashDSTU7564_384ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashDSTU7564_384ActionPerformed
        try {
            String inputText = BouncyUtil.toDSTU7564_384Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashDSTU7564_384ActionPerformed

    private void btnHashDSTU7564_512ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashDSTU7564_512ActionPerformed
        try {
            String inputText = BouncyUtil.toDSTU7564_512Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashDSTU7564_512ActionPerformed

    private void btnHashBLAKE2B_160ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashBLAKE2B_160ActionPerformed
        try {
            String inputText = BouncyUtil.toBLAKE2B_160Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashBLAKE2B_160ActionPerformed

    private void btnHashBLAKE2B_256ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashBLAKE2B_256ActionPerformed
        try {
            String inputText = BouncyUtil.toBLAKE2B_256Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashBLAKE2B_256ActionPerformed

    private void btnHashBLAKE2B_384ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashBLAKE2B_384ActionPerformed
        try {
            String inputText = BouncyUtil.toBLAKE2B_384Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashBLAKE2B_384ActionPerformed

    private void btnHashBLAKE2B_512ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashBLAKE2B_512ActionPerformed
        try {
            String inputText = BouncyUtil.toBLAKE2B_512Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashBLAKE2B_512ActionPerformed

    private void btnHashBLAKE2S_128ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashBLAKE2S_128ActionPerformed
        try {
            String inputText = BouncyUtil.toBLAKE2S_128Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashBLAKE2S_128ActionPerformed

    private void btnHashBLAKE2S_160ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashBLAKE2S_160ActionPerformed
        try {
            String inputText = BouncyUtil.toBLAKE2S_160Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashBLAKE2S_160ActionPerformed

    private void btnHashBLAKE2_S224ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashBLAKE2_S224ActionPerformed
        try {
            String inputText = BouncyUtil.toBLAKE2S_224Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashBLAKE2_S224ActionPerformed

    private void btnHashBLAKE2S_256ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashBLAKE2S_256ActionPerformed
        try {
            String inputText = BouncyUtil.toBLAKE2S_256Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashBLAKE2S_256ActionPerformed

    private void btnHashBLAKE3_256ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashBLAKE3_256ActionPerformed
        try {
            String inputText = BouncyUtil.toBLAKE3_256Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashBLAKE3_256ActionPerformed

    private void btnHashPARALLELHASH128_256ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashPARALLELHASH128_256ActionPerformed
        try {
            String inputText = BouncyUtil.toPARALLELHASH128_256Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashPARALLELHASH128_256ActionPerformed

    private void btnHashPARALLELHASH256_512ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashPARALLELHASH256_512ActionPerformed
        try {
            String inputText = BouncyUtil.toPARALLELHASH256_512Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashPARALLELHASH256_512ActionPerformed

    private void btnHashTUPLEHASH128_256ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashTUPLEHASH128_256ActionPerformed
        try {
            String inputText = BouncyUtil.toTUPLEHASH128_256Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashTUPLEHASH128_256ActionPerformed

    private void btnHashTUPLEHASH256_512ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashTUPLEHASH256_512ActionPerformed
        try {
            String inputText = BouncyUtil.toTUPLEHASH256_512Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashTUPLEHASH256_512ActionPerformed

    private void btnHashMd4ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashMd4ActionPerformed
        try {
            String inputText = BouncyUtil.toMD4Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashMd4ActionPerformed

    private void btnDotOctAIPActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnDotOctAIPActionPerformed
        SwingUtil.systemClipboardCopy(this.txtDotOctAIP.getText());
    }//GEN-LAST:event_btnDotOctAIPActionPerformed

    private void btnDotBOctIPActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnDotBOctIPActionPerformed
        SwingUtil.systemClipboardCopy(this.txtDotOctBIP.getText());
    }//GEN-LAST:event_btnDotBOctIPActionPerformed

    private void txtDotOctBIPActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_txtDotOctBIPActionPerformed
        SwingUtil.systemClipboardCopy(this.txtDotOctBIP.getText());
    }//GEN-LAST:event_txtDotOctBIPActionPerformed

    private void btnIPv4ToUnicodeActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnIPv4ToUnicodeActionPerformed
        SwingUtil.systemClipboardCopy(this.txtIPv4ToUnicode.getText());
    }//GEN-LAST:event_btnIPv4ToUnicodeActionPerformed

    private void btnDotAHexIP1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnDotAHexIP1ActionPerformed
        SwingUtil.systemClipboardCopy(this.txtIPv4MappedIPv6.getText());
    }//GEN-LAST:event_btnDotAHexIP1ActionPerformed

    private void btnDotDecAIPActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnDotDecAIPActionPerformed
        SwingUtil.systemClipboardCopy(this.txtDotDecAIP.getText());
    }//GEN-LAST:event_btnDotDecAIPActionPerformed

    private void btnDotDecBIPActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnDotDecBIPActionPerformed
        SwingUtil.systemClipboardCopy(this.txtDotDecBIP.getText());
    }//GEN-LAST:event_btnDotDecBIPActionPerformed

    private void btnDotHexAIPActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnDotHexAIPActionPerformed
        SwingUtil.systemClipboardCopy(this.txtDotHexAIP.getText());
    }//GEN-LAST:event_btnDotHexAIPActionPerformed

    private void btnDotHexBIPActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnDotHexBIPActionPerformed
        SwingUtil.systemClipboardCopy(this.txtDotHexBIP.getText());
    }//GEN-LAST:event_btnDotHexBIPActionPerformed

    private void btnIntIPActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnIntIPActionPerformed
        SwingUtil.systemClipboardCopy(this.txtIntIP.getText());
    }//GEN-LAST:event_btnIntIPActionPerformed

    private void btnDotHexCIPActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnDotHexCIPActionPerformed
        SwingUtil.systemClipboardCopy(this.txtDotHexCIP.getText());
    }//GEN-LAST:event_btnDotHexCIPActionPerformed

    private void btnHexIPActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHexIPActionPerformed
        SwingUtil.systemClipboardCopy(this.txtHexIP.getText());
    }//GEN-LAST:event_btnHexIPActionPerformed

    private void btnOctIPActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnOctIPActionPerformed
        SwingUtil.systemClipboardCopy(this.txtOctIP.getText());
    }//GEN-LAST:event_btnOctIPActionPerformed

    private void btnDotOctCIPActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnDotOctCIPActionPerformed
        SwingUtil.systemClipboardCopy(this.txtDotOctCIP.getText());
    }//GEN-LAST:event_btnDotOctCIPActionPerformed

    private void btnDecIPConvertActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnDecIPConvertActionPerformed
        int dec1 = ConvertUtil.parseIntDefault(this.txtDec1.getText(), -1);
        int dec2 = ConvertUtil.parseIntDefault(this.txtDec2.getText(), -1);
        int dec3 = ConvertUtil.parseIntDefault(this.txtDec3.getText(), -1);
        int dec4 = ConvertUtil.parseIntDefault(this.txtDec4.getText(), -1);
        if (dec1 < 0 || dec2 < 0 || dec3 < 0 || dec4 < 0) {
            this.lblIPValid.setText("IP addres Invalid");
            return;
        }
        if (!(0 <= dec1 && dec1 <= 255
            && 0 <= dec2 && dec2 <= 255
            && 0 <= dec3 && dec3 <= 255
            && 0 <= dec4 && dec4 <= 255)) {
        this.lblIPValid.setText("IP addres renge Invalid");
        return;
        }

        this.txtDotDecBIP.setText(IpUtil.IPv4ToDotBDec(dec1, dec2, dec3, dec4));
        this.txtDotDecAIP.setText(IpUtil.IPv4ToDotADec(dec1, dec2, dec3, dec4));
        this.txtIntIP.setText(IpUtil.IPv4ToInt(dec1, dec2, dec3, dec4));
        this.txtDotTailDecCIP.setText(IpUtil.IPv4ToDotCDec(dec1, dec2, dec3, dec4) + ".");
        this.txtDotOctCIP.setText(IpUtil.IPv4ToDotCOct(dec1, dec2, dec3, dec4));
        this.txtDotOctBIP.setText(IpUtil.IPv4ToDotBOct(dec1, dec2, dec3, dec4));
        this.txtDotOctAIP.setText(IpUtil.IPv4ToDotAOct(dec1, dec2, dec3, dec4));
        this.txtOctIP.setText(IpUtil.IPv4ToOct(dec1, dec2, dec3, dec4));
        this.txtDotHexCIP.setText(IpUtil.IPv4ToDotCHex(dec1, dec2, dec3, dec4));
        this.txtDotHexBIP.setText(IpUtil.IPv4ToDotBHex(dec1, dec2, dec3, dec4));
        this.txtDotHexAIP.setText(IpUtil.IPv4ToDotAHex(dec1, dec2, dec3, dec4));
        this.txtHexIP.setText(IpUtil.IPv4ToHex(dec1, dec2, dec3, dec4));
        this.txtIPv4MappedIPv6.setText(IpUtil.IPv4MappedIPv6(IpUtil.IPv4ToDotCDec(dec1, dec2, dec3, dec4)));
        this.txtIPv4ToUnicode.setText(IpUtil.IPv4ToUnicodeDigit(IpUtil.IPv4ToDotCDec(dec1, dec2, dec3, dec4)));
    }//GEN-LAST:event_btnDecIPConvertActionPerformed

    private void btnDecIPPasteActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnDecIPPasteActionPerformed
        try {
            byte ipv4[] = IpUtil.parseIPv4AddressByte(SwingUtil.systemClipboardPaste());
            this.txtDec1.setText(String.valueOf(Byte.toUnsignedInt(ipv4[0])));
            this.txtDec2.setText(String.valueOf(Byte.toUnsignedInt(ipv4[1])));
            this.txtDec3.setText(String.valueOf(Byte.toUnsignedInt(ipv4[2])));
            this.txtDec4.setText(String.valueOf(Byte.toUnsignedInt(ipv4[3])));
        } catch (ParseException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnDecIPPasteActionPerformed

    private void btnDotTailDecCIPActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnDotTailDecCIPActionPerformed
        SwingUtil.systemClipboardCopy(this.txtDotTailDecCIP.getText());
    }//GEN-LAST:event_btnDotTailDecCIPActionPerformed

    private void txtDotDecBIPActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_txtDotDecBIPActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_txtDotDecBIPActionPerformed

    private void btnHashISAPActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashISAPActionPerformed
        try {
            String inputText = BouncyUtil.toISAPSum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashISAPActionPerformed

    private void btnHashAsconActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashAsconActionPerformed
        try {
            String inputText = BouncyUtil.toAsconHash(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashAsconActionPerformed

    private void btnHashAsconAActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashAsconAActionPerformed
        try {
            String inputText = BouncyUtil.toAsconHashA(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashAsconAActionPerformed

    private void btnHashAsconXofActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashAsconXofActionPerformed
        try {
            String inputText = BouncyUtil.toAsconXof(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashAsconXofActionPerformed

    private void btnHashAsconXofAActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashAsconXofAActionPerformed
        try {
            String inputText = BouncyUtil.toAsconXofA(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashAsconXofAActionPerformed

    private void btnHashESCH256ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashESCH256ActionPerformed
        try {
            String inputText = BouncyUtil.toESCH256Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashESCH256ActionPerformed

    private void btnHashESCH384ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashESCH384ActionPerformed
        try {
            String inputText = BouncyUtil.toESCH384Sum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashESCH384ActionPerformed

    private void btnHashPhotonBeetleActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashPhotonBeetleActionPerformed
        try {
            String inputText = BouncyUtil.toPhotonBeetleSum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashPhotonBeetleActionPerformed

    private void btnHashXoodyakActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnHashXoodyakActionPerformed
        try {
            String inputText = BouncyUtil.toXoodyakSum(getInputText(),
                    this.getSelectEncode(), this.rdoUpperCase.isSelected());
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnHashXoodyakActionPerformed

    private void btnXXHash32ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnXXHash32ActionPerformed
        try {
            String inputText = Long.toString(CodecUtil.toXXHash32(getInputText(), this.getSelectEncode()));
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnXXHash32ActionPerformed

    private void btnMurmurHash3_32x86ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnMurmurHash3_32x86ActionPerformed
        try {
            String inputText = Integer.toString(CodecUtil.toMurmurHash3_32x86(getInputText(), this.getSelectEncode()));
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnMurmurHash3_32x86ActionPerformed

    private void btnMurmurHash3_128x64ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnMurmurHash3_128x64ActionPerformed
        try {
            BigInteger hash = CodecUtil.toMurmurHash3_128x64(getInputText(), this.getSelectEncode());
            String inputText = hash.toString();
            this.setOutput(inputText);
        } catch (UnsupportedEncodingException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }//GEN-LAST:event_btnMurmurHash3_128x64ActionPerformed

    private void btnZoneDateGMTCopyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnZoneDateGMTCopyActionPerformed
        SwingUtil.systemClipboardCopy(this.txtSystemZoneDateGMT.getText());
    }//GEN-LAST:event_btnZoneDateGMTCopyActionPerformed

    private void cmbTimezoneActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cmbTimezoneActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_cmbTimezoneActionPerformed

    private void cmbAlgorithmItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_cmbAlgorithmItemStateChanged
        int[] keysize_list = new int[0];
        String algo = this.getAlgorithm();
        if ("RSA".equals(algo)) {
            keysize_list = RSA_KEYSIZE;
        } else if ("DSA".equals(algo)) {
            keysize_list = DSA_KEYSIZE;
        } else if ("EC".equals(algo)) {
            keysize_list = EC_KEYSIZE;
        } else if ("Ed25519".equals(algo)) {
            keysize_list = ED25519_KEYSIZE;
        } else if ("Ed448".equals(algo)) {
            keysize_list = ED448_KEYSIZE;
        }
        List<AbstractButton> rdoGroup = ConvertUtil.toList(this.btnGrpKeySize.getElements().asIterator());
        for (int i = 0; i < rdoGroup.size(); i++) {
            this.btnGrpKeySize.remove(rdoGroup.get(i));
        }
        this.pnlKeySize.removeAll();
        for (int i = 0; i < keysize_list.length; i++) {
            javax.swing.JRadioButton rdoKeySize = new javax.swing.JRadioButton();
            if (i == (keysize_list.length / 2)) {
                rdoKeySize.setSelected(true);
            }
            rdoKeySize.setText(String.valueOf(keysize_list[i]));
            rdoKeySize.setActionCommand(String.valueOf(keysize_list[i]));
            this.pnlKeySize.add(rdoKeySize);
            this.btnGrpKeySize.add(rdoKeySize);
        }
        this.pnlKeySize.updateUI();
    }//GEN-LAST:event_cmbAlgorithmItemStateChanged

    private void btnGeneClearActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnGeneClearActionPerformed
        this.txtGenarate.setText("");
    }//GEN-LAST:event_btnGeneClearActionPerformed

    public String exportKeyPairToPem() {
        String algo = getAlgorithm();
        if ("DSA".equals(algo) && this.rdoConvertKeyPairJWK.isSelected()) {
            throw new UnsupportedOperationException("Unsupport algorithm:" + algo);
        }
        StringWriter exportKeyPair = new StringWriter();
        KeyPair keyPair = this.getExportKeyPair();
        if (keyPair != null) {
            try {
                if (this.rdoConvertKeyPairPEM.isSelected()) {
                    String key = BouncyUtil.exportKeyPairPem(keyPair);
                    exportKeyPair.append(key);
                }
                else if (this.rdoConvertKeyPairJWK.isSelected()) {
                    String jwk = JWKToken.toJWK(keyPair, true);
                    exportKeyPair.append(jwk);
                }
            } catch (InvalidKeySpecException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            } catch (IOException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        } else {
            throw new UnsupportedOperationException("No KeyPair has been selected.:" + algo);
        }
        return exportKeyPair.toString();
    }


    private final java.awt.event.ActionListener historyActionPerformed = new java.awt.event.ActionListener() {
        @Override
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
    private javax.swing.JButton btnCRC32C;
    private javax.swing.JButton btnCalc;
    private javax.swing.JButton btnClear;
    private javax.swing.ButtonGroup btnConvertCase;
    private javax.swing.JButton btnDecCopy;
    private javax.swing.JButton btnDecIPConvert;
    private javax.swing.JButton btnDecIPPaste;
    private javax.swing.JButton btnDecode;
    private javax.swing.JButton btnDotAHexIP1;
    private javax.swing.JButton btnDotBOctIP;
    private javax.swing.JButton btnDotDecAIP;
    private javax.swing.JButton btnDotDecBIP;
    private javax.swing.JButton btnDotHexAIP;
    private javax.swing.JButton btnDotHexBIP;
    private javax.swing.JButton btnDotHexCIP;
    private javax.swing.JButton btnDotOctAIP;
    private javax.swing.JButton btnDotOctCIP;
    private javax.swing.JButton btnDotTailDecCIP;
    private javax.swing.JButton btnEncode;
    private javax.swing.JButton btnExcelSerial;
    private javax.swing.JButton btnGeneClear;
    private javax.swing.JButton btnGeneCopy;
    private javax.swing.JButton btnGeneSavetoFile;
    private javax.swing.JButton btnGenerate;
    private javax.swing.ButtonGroup btnGrpEncodeType;
    private javax.swing.ButtonGroup btnGrpExportKeyPair;
    private javax.swing.ButtonGroup btnGrpKeySize;
    private javax.swing.ButtonGroup btnGrpNewLine;
    private javax.swing.JButton btnHashAscon;
    private javax.swing.JButton btnHashAsconA;
    private javax.swing.JButton btnHashAsconXof;
    private javax.swing.JButton btnHashAsconXofA;
    private javax.swing.JButton btnHashBLAKE2B_160;
    private javax.swing.JButton btnHashBLAKE2B_256;
    private javax.swing.JButton btnHashBLAKE2B_384;
    private javax.swing.JButton btnHashBLAKE2B_512;
    private javax.swing.JButton btnHashBLAKE2S_128;
    private javax.swing.JButton btnHashBLAKE2S_160;
    private javax.swing.JButton btnHashBLAKE2S_256;
    private javax.swing.JButton btnHashBLAKE2_S224;
    private javax.swing.JButton btnHashBLAKE3_256;
    private javax.swing.JButton btnHashDSTU7564_256;
    private javax.swing.JButton btnHashDSTU7564_384;
    private javax.swing.JButton btnHashDSTU7564_512;
    private javax.swing.JButton btnHashESCH256;
    private javax.swing.JButton btnHashESCH384;
    private javax.swing.JButton btnHashGOST3411;
    private javax.swing.JButton btnHashGOST3411_2012_256;
    private javax.swing.JButton btnHashGOST3411_2012_512;
    private javax.swing.JButton btnHashHARAKA256;
    private javax.swing.JButton btnHashHARAKA512;
    private javax.swing.JButton btnHashISAP;
    private javax.swing.JButton btnHashKECCAK224;
    private javax.swing.JButton btnHashKECCAK256;
    private javax.swing.JButton btnHashKECCAK288;
    private javax.swing.JButton btnHashKECCAK384;
    private javax.swing.JButton btnHashKECCAK512;
    private javax.swing.JButton btnHashMd2;
    private javax.swing.JButton btnHashMd4;
    private javax.swing.JButton btnHashMd5;
    private javax.swing.JButton btnHashPARALLELHASH128_256;
    private javax.swing.JButton btnHashPARALLELHASH256_512;
    private javax.swing.JButton btnHashPhotonBeetle;
    private javax.swing.JButton btnHashRIPEMD128;
    private javax.swing.JButton btnHashRIPEMD129;
    private javax.swing.JButton btnHashRIPEMD256;
    private javax.swing.JButton btnHashRIPEMD320;
    private javax.swing.JButton btnHashSHAKE128;
    private javax.swing.JButton btnHashSHAKE256;
    private javax.swing.JButton btnHashSKEIN1024_1024;
    private javax.swing.JButton btnHashSKEIN1024_384;
    private javax.swing.JButton btnHashSKEIN1024_512;
    private javax.swing.JButton btnHashSKEIN256_128;
    private javax.swing.JButton btnHashSKEIN256_160;
    private javax.swing.JButton btnHashSKEIN256_224;
    private javax.swing.JButton btnHashSKEIN256_256;
    private javax.swing.JButton btnHashSKEIN512_128;
    private javax.swing.JButton btnHashSKEIN512_160;
    private javax.swing.JButton btnHashSKEIN512_224;
    private javax.swing.JButton btnHashSKEIN512_256;
    private javax.swing.JButton btnHashSKEIN512_384;
    private javax.swing.JButton btnHashSKEIN512_512;
    private javax.swing.JButton btnHashSM3;
    private javax.swing.JButton btnHashSha1;
    private javax.swing.JButton btnHashSha224;
    private javax.swing.JButton btnHashSha256;
    private javax.swing.JButton btnHashSha384;
    private javax.swing.JButton btnHashSha3_224;
    private javax.swing.JButton btnHashSha3_256;
    private javax.swing.JButton btnHashSha3_384;
    private javax.swing.JButton btnHashSha3_512;
    private javax.swing.JButton btnHashSha512;
    private javax.swing.JButton btnHashSha512_224;
    private javax.swing.JButton btnHashSha512_256;
    private javax.swing.JButton btnHashTUPLEHASH128_256;
    private javax.swing.JButton btnHashTUPLEHASH256_512;
    private javax.swing.JButton btnHashTiger;
    private javax.swing.JButton btnHashWHIRLPOOL;
    private javax.swing.JButton btnHashXoodyak;
    private javax.swing.JButton btnHexCopy;
    private javax.swing.JButton btnHexIP;
    private javax.swing.JButton btnIPv4ToUnicode;
    private javax.swing.JButton btnInputfile;
    private javax.swing.JButton btnIntIP;
    private javax.swing.JButton btnJavaSerialCopy;
    private javax.swing.JButton btnMurmurHash2_32;
    private javax.swing.JButton btnMurmurHash2_64;
    private javax.swing.JButton btnMurmurHash3_128x64;
    private javax.swing.JButton btnMurmurHash3_32x86;
    private javax.swing.JButton btnOctCopy;
    private javax.swing.JButton btnOctIP;
    private javax.swing.JPanel btnOutput;
    private javax.swing.JButton btnOutputCopy;
    private javax.swing.JButton btnOutputToInput;
    private javax.swing.JButton btnOutputfile;
    private javax.swing.JButton btnRadix32Copy;
    private javax.swing.JButton btnSmartDecode;
    private javax.swing.JButton btnSmartFormat;
    private javax.swing.JButton btnSmartMatch;
    private javax.swing.JButton btnUnixtimeCopy;
    private javax.swing.JButton btnXXHash32;
    private javax.swing.JButton btnZoneDateCopy;
    private javax.swing.JButton btnZoneDateGMTCopy;
    private javax.swing.JCheckBox chk64Newline;
    private javax.swing.JCheckBox chk76Newline;
    private javax.swing.JCheckBox chkCharacterCustom;
    private javax.swing.JCheckBox chkCharacterLowerCase;
    private javax.swing.JCheckBox chkCharacterNumber;
    private javax.swing.JCheckBox chkCharacterSpace;
    private javax.swing.JCheckBox chkCharacterUnderline;
    private javax.swing.JCheckBox chkCharacterUpperCase;
    private javax.swing.JCheckBox chkGuess;
    private javax.swing.JCheckBox chkMetaChar;
    private javax.swing.JCheckBox chkNPadding;
    private javax.swing.JCheckBox chkPadding;
    private javax.swing.JCheckBox chkRawMode;
    private javax.swing.JCheckBox chkViewLineWrap;
    private javax.swing.JCheckBox chkWithByte;
    private javax.swing.JComboBox<String> cmbAlgorithm;
    private javax.swing.JComboBox<String> cmbDateUnit;
    private javax.swing.JComboBox<String> cmbEncoding;
    private javax.swing.JComboBox<String> cmbHistory;
    private javax.swing.JComboBox cmbIILUTF8;
    private javax.swing.JComboBox<String> cmbTimezone;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JLabel lbAlgorithm;
    private javax.swing.JLabel lblBin;
    private javax.swing.JLabel lblDate;
    private javax.swing.JLabel lblDateEnd;
    private javax.swing.JLabel lblDateFormat;
    private javax.swing.JLabel lblDateGMT;
    private javax.swing.JLabel lblDateStart;
    private javax.swing.JLabel lblDateStep;
    private javax.swing.JLabel lblDec;
    private javax.swing.JLabel lblDotDeclIP;
    private javax.swing.JLabel lblDotDectAIP;
    private javax.swing.JLabel lblDotDectBIP;
    private javax.swing.JLabel lblDotHexAIP;
    private javax.swing.JLabel lblDotHexBIP;
    private javax.swing.JLabel lblDotHexCIP;
    private javax.swing.JLabel lblDotOcBtIP;
    private javax.swing.JLabel lblDotOctAIP;
    private javax.swing.JLabel lblDotOctCIP;
    private javax.swing.JLabel lblExcelSerial;
    private javax.swing.JLabel lblHex;
    private javax.swing.JLabel lblHexIP;
    private javax.swing.JLabel lblIPValid;
    private javax.swing.JLabel lblIPv4MappedIPv6;
    private javax.swing.JLabel lblIPv4toUnicode;
    private javax.swing.JLabel lblIntIP;
    private javax.swing.JLabel lblJavaSerial;
    private javax.swing.JLabel lblKeyPairValid;
    private javax.swing.JLabel lblKeySize;
    private javax.swing.JLabel lblNumEnd;
    private javax.swing.JLabel lblNumFormat;
    private javax.swing.JLabel lblNumStart;
    private javax.swing.JLabel lblNumStep;
    private javax.swing.JLabel lblOct;
    private javax.swing.JLabel lblOctIP;
    private javax.swing.JLabel lblPositionStatus;
    private javax.swing.JLabel lblRadix32;
    private javax.swing.JLabel lblTailDotDecCIP;
    private javax.swing.JLabel lblUnixtime;
    private javax.swing.JLabel lblZoneDate;
    private javax.swing.JLabel lblmaximum;
    private javax.swing.JPanel pnlBase64;
    private javax.swing.JPanel pnlBase64URLSafe;
    private javax.swing.JPanel pnlBaseN;
    private javax.swing.JPanel pnlBottom;
    private javax.swing.JPanel pnlCharacter;
    private javax.swing.JPanel pnlCheckSumTrans;
    private javax.swing.JPanel pnlCompress;
    private javax.swing.JPanel pnlConvert;
    private javax.swing.JPanel pnlConvertCase;
    private javax.swing.JPanel pnlCount;
    private javax.swing.JPanel pnlCustom;
    private javax.swing.JPanel pnlDate;
    private javax.swing.JPanel pnlDotDecIP;
    private javax.swing.JPanel pnlEncDec;
    private javax.swing.JPanel pnlEncode;
    private javax.swing.JPanel pnlEncodeDecode;
    private javax.swing.JPanel pnlEncoding;
    private javax.swing.JPanel pnlFormat;
    private javax.swing.JPanel pnlGenerate;
    private javax.swing.JPanel pnlGenerateKey;
    private javax.swing.JPanel pnlHashCheckSum;
    private javax.swing.JPanel pnlHashTrans;
    private javax.swing.JPanel pnlHeader;
    private javax.swing.JPanel pnlHtmlEnc;
    private javax.swing.JPanel pnlHtmlHex;
    private javax.swing.JPanel pnlILLUTF8;
    private javax.swing.JPanel pnlInput;
    private javax.swing.JPanel pnlInputOutput;
    private javax.swing.JPanel pnlInputRaw;
    private javax.swing.JPanel pnlJSHexEnc;
    private javax.swing.JPanel pnlJSUnicodeEnc;
    private javax.swing.JPanel pnlKeyPairAlgorithm;
    private javax.swing.JPanel pnlKeyPairConvertFormat;
    private javax.swing.JPanel pnlKeySize;
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
    private javax.swing.JPanel pnlTransAction;
    private javax.swing.JPanel pnlTranslator;
    private javax.swing.JPanel pnlUrl;
    private javax.swing.JPanel pnlWrap;
    private javax.swing.JRadioButton rdoAll;
    private javax.swing.JRadioButton rdoAlphaNum;
    private javax.swing.JRadioButton rdoBase16;
    private javax.swing.JRadioButton rdoBase32;
    private javax.swing.JRadioButton rdoBase64;
    private javax.swing.JRadioButton rdoBase64URLSafe;
    private javax.swing.JRadioButton rdoBase64andURL;
    private javax.swing.JRadioButton rdoBeautifyFormat;
    private javax.swing.JRadioButton rdoByteHex2;
    private javax.swing.JRadioButton rdoByteNoneHex;
    private javax.swing.JRadioButton rdoByteOct;
    private javax.swing.JRadioButton rdoByteXHex;
    private javax.swing.JRadioButton rdoCLang;
    private javax.swing.JRadioButton rdoCR;
    private javax.swing.JRadioButton rdoCRLF;
    private javax.swing.ButtonGroup rdoCetificateGrp;
    private javax.swing.JRadioButton rdoConvertKeyPairJWK;
    private javax.swing.JRadioButton rdoConvertKeyPairPEM;
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
    private javax.swing.JRadioButton rdoHtmlUnicode;
    private javax.swing.JRadioButton rdoILLUTF8;
    private javax.swing.JRadioButton rdoJSON;
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
    private javax.swing.JRadioButton rdoURLSafe;
    private javax.swing.JRadioButton rdoUTF7;
    private javax.swing.JRadioButton rdoUnicodeHex;
    private javax.swing.JRadioButton rdoUnicodeHex2;
    private javax.swing.JRadioButton rdoUpperCase;
    private javax.swing.JRadioButton rdoUrl;
    private javax.swing.JRadioButton rdoUrlUnicode;
    private javax.swing.JRadioButton rdoZLIB;
    private javax.swing.JRadioButton rdoZLIB_NOWRAP;
    private javax.swing.JScrollPane scrollGenerate;
    private javax.swing.JScrollPane scrollStatus;
    private javax.swing.JSplitPane splitConvert;
    private javax.swing.JSplitPane splitGenerator;
    private javax.swing.JSpinner spnCountNum;
    private javax.swing.JSpinner spnDateEnd;
    private javax.swing.JSpinner spnDateStart;
    private javax.swing.JSpinner spnDateStep;
    private javax.swing.JSpinner spnLengthNum;
    private javax.swing.JSpinner spnNumEnd;
    private javax.swing.JSpinner spnNumStart;
    private javax.swing.JSpinner spnNumStep;
    private javax.swing.JSpinner spnZoneDateTime;
    private javax.swing.JPanel tabBaseConverter;
    private javax.swing.JPanel tabDateConverter;
    private javax.swing.JPanel tabGenerator;
    private javax.swing.JPanel tabIPFormatConverter;
    private javax.swing.JPanel tabRandom;
    private javax.swing.JPanel tabSequence;
    private javax.swing.JPanel tabTokenStrength;
    private javax.swing.JPanel tabTransrator;
    private javax.swing.JTabbedPane tabbetConverter;
    private javax.swing.JTabbedPane tabbetGenerate;
    private javax.swing.JTabbedPane tabbetInput;
    private javax.swing.JTabbedPane tabbetOutput;
    private javax.swing.JTabbedPane tabbetSequence;
    private javax.swing.JTabbedPane tabbetTransAction;
    private javax.swing.JTabbedPane tabbetTranscoder;
    private javax.swing.JTextField txtBase;
    private javax.swing.JTextField txtBin;
    private javax.swing.JTextField txtCustom;
    private javax.swing.JTextField txtDateFormat;
    private javax.swing.JTextField txtDec;
    private javax.swing.JTextField txtDec1;
    private javax.swing.JTextField txtDec2;
    private javax.swing.JTextField txtDec3;
    private javax.swing.JTextField txtDec4;
    private javax.swing.JTextField txtDotDecAIP;
    private javax.swing.JTextField txtDotDecBIP;
    private javax.swing.JTextField txtDotHexAIP;
    private javax.swing.JTextField txtDotHexBIP;
    private javax.swing.JTextField txtDotHexCIP;
    private javax.swing.JTextField txtDotOctAIP;
    private javax.swing.JTextField txtDotOctBIP;
    private javax.swing.JTextField txtDotOctCIP;
    private javax.swing.JTextField txtDotTailDecCIP;
    private javax.swing.JFormattedTextField txtExcelSerial;
    private javax.swing.JTextField txtExponent;
    private javax.swing.JTextArea txtGenarate;
    private javax.swing.JTextField txtHex;
    private javax.swing.JTextField txtHexIP;
    private javax.swing.JTextField txtIPv4MappedIPv6;
    private javax.swing.JTextField txtIPv4ToUnicode;
    private javax.swing.JTextField txtIntIP;
    private javax.swing.JFormattedTextField txtJavaSerial;
    private javax.swing.JTextField txtNumFormat;
    private javax.swing.JTextField txtOct;
    private javax.swing.JTextField txtOctIP;
    private javax.swing.JTextField txtRadix32;
    private javax.swing.JTextArea txtStatus;
    private javax.swing.JTextField txtStrength;
    private javax.swing.JTextField txtSystemZoneDate;
    private javax.swing.JTextField txtSystemZoneDateGMT;
    private javax.swing.JTextArea txtTokenList;
    private javax.swing.JFormattedTextField txtUnixtime;
    // End of variables declaration//GEN-END:variables

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
                formatArgsList[i + 0] = ConvertUtil.toHexString(encodeCodeList.get((int) i / 2), true);
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

        } catch (UnsupportedEncodingException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
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
            boolean metaChar = this.chkMetaChar.isSelected();
            String decode = TransUtil.toSmartDecode(inputText, encodePattern, metaChar, applyCharset);
            this.setOutput(decode, applyCharset);
        } catch (java.lang.NumberFormatException ex) {
            this.setOutputText(StringUtil.getStackTraceMessage(ex));
            logger.log(Level.INFO, ex.getMessage(), ex);
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
        try {
            this.setOutputByte(StringUtil.getBytesCharset(outputText, encoding));
        } catch (UnsupportedEncodingException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
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
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    void sendToJTransCoder(String text) {
        this.setInputText(text);
        this.setInputByte(StringUtil.getBytesRaw(text));
    }

    byte[] receiveFromJTransCoder() {
        return this.getOutputByte();
    }

    public void sendToJWSDecoder(String header, String payload, String signature) {
        if (header != null) this.jwsDecoderTab.setHeaderJSON(header, true);
        if (payload != null) this.jwsDecoderTab.setPayloadJSON(payload, true);
        if (signature != null) this.jwsDecoderTab.setSignature(signature);
    }

    public void sendToJWSEncoder(String header, String payload, String secret) {
        this.jwsEncoderTab.setSelectedAlgorithm(null);
        if (header != null) this.jwsEncoderTab.setHeaderJSON(header, true);
        if (payload != null) this.jwsEncoderTab.setPayloadJSON(payload, true);
        if (secret != null) this.jwsEncoderTab.setSecretKey(secret);
        if (this.jwsEncoderTab.getHeader() != null) {
            JWSToken.Algorithm algo = this.jwsEncoderTab.getHeader().getAlgorithm();
            this.jwsEncoderTab.setSelectedAlgorithm(algo);
        }
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
        } else if (this.rdoURLSafe.isSelected()) {
            return EncodeType.BURP_LIKE;
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
            case BURP_LIKE:
                this.rdoURLSafe.setSelected(true);
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


    protected String getAlgorithm() {
        return (String) this.cmbAlgorithm.getSelectedItem();
    }

    protected int getKeySize() {
        ButtonModel model = this.btnGrpKeySize.getSelection();
        return Integer.parseInt(model.getActionCommand());
    }

    private KeyPair getExportKeyPair() {
        try {
            String algo = this.getAlgorithm();
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algo);
            if (KEY_USE_MAP.getOrDefault(algo, Boolean.FALSE)) {
                keyGen.initialize(this.getKeySize());
            }
            KeyPair keyPair = keyGen.generateKeyPair();
            return keyPair;
        } catch (NoSuchAlgorithmException ex) {
            this.lblKeyPairValid.setText(BUNDLE.getString("keypair.invalid.algorithm"));
        } catch (InvalidParameterException ex) {
            this.lblKeyPairValid.setText(BUNDLE.getString("keypair.invalid.keysize"));
        } catch (ProviderException ex) {
            this.lblKeyPairValid.setText(BUNDLE.getString("keypair.invalid.keysize"));
        }
        return null;
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

    @Override
    public void extensionUnloaded() {
        this.certificateTab.stopMockServer();
    }

}
