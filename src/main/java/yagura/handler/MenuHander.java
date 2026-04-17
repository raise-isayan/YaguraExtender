package yagura.handler;

import burp.BurpExtension;
import burp.api.montoya.MontoyaApi;
import extension.helpers.BouncyUtil;
import extend.util.external.CodecUtil;
import extend.util.external.TransUtil;
import extension.burp.BurpConfig;
import extension.burp.BurpHotKey;
import extension.burp.BurpUtil;
import extension.burp.FilterProperty;
import extension.burp.IBurpTab;
import extension.burp.TargetScopeItem;
import extension.helpers.ConvertUtil;
import extension.helpers.HttpUtil;
import extension.helpers.SmartCodec;
import extension.helpers.StringUtil;
import extension.helpers.SwingUtil;
import java.awt.Component;
import java.awt.KeyboardFocusManager;
import java.awt.event.ActionEvent;
import java.awt.event.HierarchyEvent;
import java.awt.event.HierarchyListener;
import java.awt.event.KeyEvent;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Stream;
import javax.swing.AbstractButton;
import javax.swing.ButtonGroup;
import javax.swing.ButtonModel;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JRadioButtonMenuItem;
import javax.swing.JTextArea;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.event.MenuEvent;
import javax.swing.event.MenuListener;
import yagura.model.HostName;
import yagura.model.HostNameEntry;
import yagura.model.ResultFilterProperty;
import yagura.model.SendToProperty.SendToMenuPlace;
import yagura.model.TranslateItemAction;
import yagura.view.ResultFilterDlg;

/**
 *
 * @author isayan
 */
public final class MenuHander {

    private final static Logger logger = Logger.getLogger(MenuHander.class.getName());

    private final static java.util.ResourceBundle BUNDLE = java.util.ResourceBundle.getBundle("yagura/resources/Resource");

    private final MontoyaApi api;
    private final BurpExtension extenderImpl;

    private final ButtonGroup menuBurpCharsetsGroup = new ButtonGroup();
    private final ButtonGroup menuYaguraCharsetsGroup = new ButtonGroup();
    private final ButtonGroup menuYaguraEncodeTypeGroup = new ButtonGroup();
    private final ButtonGroup menuYaguraConvertCaseGroup = new ButtonGroup();
    private final ButtonGroup menuBurpResultFilterGroup = new ButtonGroup();
    private final JMenu burpCharsetMenu = new JMenu();
    private final JMenu yaguraCharsetMenu = new JMenu();
    private final JMenu yaguraResultFilterMenu = new JMenu();
    private final static String USE_BURP_CHARSETS = "Use Burp Charsets";

    private String yaguraCharset = StandardCharsets.UTF_8.name();

    public enum MENU_ACTION {
        ENCODER, DECODER, CONVERTER, HASH;
    };

    public MenuHander(MontoyaApi api) {
        this.api = api;
        this.extenderImpl = BurpExtension.getInstance();

        final JMenu yaguraMenu = new JMenu();
        yaguraMenu.setText("Yagura");
        yaguraMenu.setMnemonic(KeyEvent.VK_Y);
        yaguraMenu.addMenuListener(new MenuListener() {
            @Override
            public void menuSelected(MenuEvent e) {
                SwingUtilities.invokeLater(new Runnable() {
                    @Override
                    public void run() {
                        updateUI();
                    }
                });
            }

            @Override
            public void menuDeselected(MenuEvent e) {
            }

            @Override
            public void menuCanceled(MenuEvent e) {
            }
        });

        /**
         * Yagura Charsets
         */
        yaguraCharsetMenu.setText("Yagura Charsets (Y)");

        yaguraCharsetMenu.setMnemonic(KeyEvent.VK_Y);

        // updateYaguraCharsetUI(this.yaguraCharsetMenu);
        yaguraMenu.add(this.yaguraCharsetMenu);

        /**
         * Yagura Encode Type
         */
        JMenu yaguraEncodTypeMenu = new JMenu();
        yaguraEncodTypeMenu.setText("Yagura Encode Type (T)");
        yaguraEncodTypeMenu.setMnemonic(KeyEvent.VK_T);

        JRadioButtonMenuItem yaguraUpperCase = new JRadioButtonMenuItem();
        yaguraUpperCase.setText("Upper Case");
        yaguraUpperCase.setMnemonic(KeyEvent.VK_U);
        yaguraUpperCase.setActionCommand(TransUtil.ConvertCase.UPPER.name());
        yaguraUpperCase.addActionListener(this.YAGURA_CONVERT_CASE_ACTION);
        yaguraEncodTypeMenu.add(yaguraUpperCase);
        this.menuYaguraConvertCaseGroup.add(yaguraUpperCase);

        JRadioButtonMenuItem yaguraLowerCase = new JRadioButtonMenuItem();
        yaguraLowerCase.setText("Lowler Case");
        yaguraLowerCase.setMnemonic(KeyEvent.VK_L);
        yaguraLowerCase.setActionCommand(TransUtil.ConvertCase.LOWLER.name());
        yaguraLowerCase.addActionListener(this.YAGURA_CONVERT_CASE_ACTION);
        yaguraEncodTypeMenu.add(yaguraLowerCase);
        this.menuYaguraConvertCaseGroup.add(yaguraLowerCase);

        yaguraLowerCase.setSelected(true);
        yaguraEncodTypeMenu.addSeparator();

        JRadioButtonMenuItem yaguraEncodeTypeAll = new JRadioButtonMenuItem();
        yaguraEncodeTypeAll.setText(TransUtil.EncodeType.ALL.toIdent());
        yaguraEncodeTypeAll.setMnemonic(KeyEvent.VK_A);
        yaguraEncodeTypeAll.setActionCommand(TransUtil.EncodeType.ALL.name());
        yaguraEncodeTypeAll.addActionListener(this.YAGURA_ENCODE_TYPE_ACTION);
        yaguraEncodTypeMenu.add(yaguraEncodeTypeAll);
        this.menuYaguraEncodeTypeGroup.add(yaguraEncodeTypeAll);

        JRadioButtonMenuItem yaguraEncodeTypeAlphanum = new JRadioButtonMenuItem();
        yaguraEncodeTypeAlphanum.setText(TransUtil.EncodeType.ALPHANUM.toIdent());
        yaguraEncodeTypeAlphanum.setMnemonic(KeyEvent.VK_N);
        yaguraEncodeTypeAlphanum.setActionCommand(TransUtil.EncodeType.ALPHANUM.name());
        yaguraEncodeTypeAlphanum.addActionListener(this.YAGURA_ENCODE_TYPE_ACTION);
        yaguraEncodTypeMenu.add(yaguraEncodeTypeAlphanum);
        this.menuYaguraEncodeTypeGroup.add(yaguraEncodeTypeAlphanum);

        JRadioButtonMenuItem yaguraEncodeTypeBurpLike = new JRadioButtonMenuItem();
        yaguraEncodeTypeBurpLike.setText(TransUtil.EncodeType.BURP_LIKE.toIdent());
        yaguraEncodeTypeBurpLike.setMnemonic(KeyEvent.VK_B);
        yaguraEncodeTypeBurpLike.setActionCommand(TransUtil.EncodeType.BURP_LIKE.name());
        yaguraEncodeTypeBurpLike.addActionListener(this.YAGURA_ENCODE_TYPE_ACTION);
        yaguraEncodTypeMenu.add(yaguraEncodeTypeBurpLike);
        this.menuYaguraEncodeTypeGroup.add(yaguraEncodeTypeBurpLike);

        JRadioButtonMenuItem yaguraEncodeTypeLight = new JRadioButtonMenuItem();
        yaguraEncodeTypeLight.setText(TransUtil.EncodeType.LIGHT.toIdent());
        yaguraEncodeTypeLight.setMnemonic(KeyEvent.VK_T);
        yaguraEncodeTypeLight.setActionCommand(TransUtil.EncodeType.LIGHT.name());
        yaguraEncodeTypeLight.addActionListener(this.YAGURA_ENCODE_TYPE_ACTION);
        yaguraEncodTypeMenu.add(yaguraEncodeTypeLight);
        this.menuYaguraEncodeTypeGroup.add(yaguraEncodeTypeLight);

        JRadioButtonMenuItem yaguraEncodeTypeStandard = new JRadioButtonMenuItem();
        yaguraEncodeTypeStandard.setText(TransUtil.EncodeType.STANDARD.toIdent());
        yaguraEncodeTypeStandard.setMnemonic(KeyEvent.VK_S);
        yaguraEncodeTypeStandard.setActionCommand(TransUtil.EncodeType.STANDARD.name());
        yaguraEncodeTypeStandard.addActionListener(this.YAGURA_ENCODE_TYPE_ACTION);
        yaguraEncodTypeMenu.add(yaguraEncodeTypeStandard);
        this.menuYaguraEncodeTypeGroup.add(yaguraEncodeTypeStandard);

        yaguraMenu.add(yaguraEncodTypeMenu);

        yaguraEncodeTypeAll.setSelected(true);

        /**
         * Yagura Encoder
         */
        JMenu yaguraEncoderMenu = new JMenu();
        yaguraEncoderMenu.setText("Encoder (E)");
        yaguraEncoderMenu.setMnemonic(KeyEvent.VK_E);

        for (TranslateItemAction menuAction : MENU_ENCODE_ACTION) {
            yaguraEncoderMenu.add(createMenuItem(menuAction));
        }

        /**
         * **
         * JMenuItem yaguraEncoderURLMenu = createMenuItem("URL(%hh)",
         * KeyEvent.VK_U, this.TRANSLATE_ENCODE_URL);
         * yaguraEncoderMenu.add(yaguraEncoderURLMenu);
         *
         * JMenuItem yaguraEncoderURLUnicodeMenu =
         * createMenuItem("Unicode(%uhhhh) - URL", KeyEvent.VK_N,
         * this.TRANSLATE_ENCODE_UNICODE_URL);
         * yaguraEncoderMenu.add(yaguraEncoderURLUnicodeMenu);
         *
         * JMenuItem yaguraEncoderUnicodeMenu = createMenuItem("Unicode(\\uhhhh)
         * - JSON", KeyEvent.VK_J, this.TRANSLATE_ENCODE_UNICODE_JSON);
         * yaguraEncoderMenu.add(yaguraEncoderUnicodeMenu);
         *
         * JMenuItem yaguraEncoderBase64Menu = createMenuItem("Base64",
         * KeyEvent.VK_B, this.TRANSLATE_ENCODE_BASE64);
         * yaguraEncoderMenu.add(yaguraEncoderBase64Menu);
         *
         * JMenuItem yaguraEncoderBase64UrlSafeMenu =
         * createMenuItem("Base64URLSafe", KeyEvent.VK_S,
         * this.TRANSLATE_ENCODE_BASE64_SAFE);
         * yaguraEncoderMenu.add(yaguraEncoderBase64UrlSafeMenu);
         *
         * JMenuItem yaguraEncoderBase64andUrlMenu = createMenuItem("Base64 +
         * URL", KeyEvent.VK_A, this.TRANSLATE_ENCODE_BASE64_URL);
         * yaguraEncoderMenu.add(yaguraEncoderBase64andUrlMenu);
         *
         * JMenuItem yaguraEncoderHtmlMenu = createMenuItem("Html",
         * KeyEvent.VK_H, this.TRANSLATE_ENCODE_HTML);
         * yaguraEncoderMenu.add(yaguraEncoderHtmlMenu);
         *
         * JMenuItem yaguraEncoderMetacharMenu = createMenuItem("JSON with
         * Meta", KeyEvent.VK_M, this.TRANSLATE_ENCODE_JSON_META);
         * yaguraEncoderMenu.add(yaguraEncoderMetacharMenu);
***
         */
        yaguraMenu.add(yaguraEncoderMenu);

        /**
         * Yagura Decoder
         */
        JMenu yaguraDecoderMenu = new JMenu();
        yaguraDecoderMenu.setText("Decoder (D)");
        yaguraDecoderMenu.setMnemonic(KeyEvent.VK_D);

        for (TranslateItemAction menuAction : MENU_DECODER_ACTION) {
            yaguraDecoderMenu.add(createMenuItem(menuAction));
        }

        /**
         * **
         * JMenuItem yaguraDecoderURLMenu = createMenuItem("URL(%hh)",
         * KeyEvent.VK_U, this.TRANSLATE_DECODE_URL);
         * yaguraDecoderMenu.add(yaguraDecoderURLMenu);
         *
         * JMenuItem yaguraDecoderURLUnicodeMenu =
         * createMenuItem("Unicode(%uhhhh) - URL", KeyEvent.VK_N,
         * this.TRANSLATE_DECODE_UNICODE_URL);
         * yaguraDecoderMenu.add(yaguraDecoderURLUnicodeMenu);
         *
         * JMenuItem yaguraDecoderUnicodeMenu = createMenuItem("Unicode(\\uhhhh)
         * - JSON", KeyEvent.VK_J, this.TRANSLATE_DECODE_UNICODE_JSON);
         * yaguraDecoderMenu.add(yaguraDecoderUnicodeMenu);
         *
         * JMenuItem yaguraDecoderBase64Menu = createMenuItem("Base64",
         * KeyEvent.VK_B, this.TRANSLATE_DECODE_BASE64);
         * yaguraDecoderMenu.add(yaguraDecoderBase64Menu);
         *
         * JMenuItem yaguraDecoderBase64UrlSafeMenu =
         * createMenuItem("Base64URLSafe", KeyEvent.VK_S,
         * this.TRANSLATE_DECODE_BASE64_SAFE);
         * yaguraDecoderMenu.add(yaguraDecoderBase64UrlSafeMenu);
         *
         * JMenuItem yaguraDecoderBase64andUrlMenu = createMenuItem("Base64 +
         * URL", KeyEvent.VK_A, this.TRANSLATE_DECODE_BASE64_URL);
         * yaguraDecoderMenu.add(yaguraDecoderBase64andUrlMenu);
         *
         * JMenuItem yaguraDecoderHtmlMenu = createMenuItem("Html",
         * KeyEvent.VK_H, this.TRANSLATE_DECODE_HTML);
         * yaguraDecoderMenu.add(yaguraDecoderHtmlMenu);
         *
         * JMenuItem yaguraDecoderMetacharMenu = createMenuItem("JSON with
         * Meta", KeyEvent.VK_M, this.TRANSLATE_DECODE_JSON_META);
         * yaguraDecoderMenu.add(yaguraDecoderMetacharMenu);
***
         */
        yaguraMenu.add(yaguraDecoderMenu);

        /**
         * Yagura Converter
         */
        JMenu yaguraConverterMenu = new JMenu();
        yaguraConverterMenu.setText("Converter (C)");
        yaguraConverterMenu.setMnemonic(KeyEvent.VK_C);

        for (TranslateItemAction menuAction : MENU_CONVERT_ACTION) {
            yaguraConverterMenu.add(createMenuItem(menuAction));
        }

        /**
         * **
         * JMenuItem yaguraDecoderUpperCaseItemMenu = createMenuItem("Upper
         * Case", KeyEvent.VK_U, this.TRANSLATE_CONVERT_UPPER_CASE);
         * yaguraConverterMenu.add(yaguraDecoderUpperCaseItemMenu);
         *
         * JMenuItem yaguraDecoderLowlerCaseItemMenu = createMenuItem("Lowler
         * Case", KeyEvent.VK_L, this.TRANSLATE_CONVERT_LOWLER_CASE);
         * yaguraConverterMenu.add(yaguraDecoderLowlerCaseItemMenu);
         *
         * JMenuItem yaguraConverterBin2HexMenu = createMenuItem("bin2hex",
         * KeyEvent.VK_B, this.TRANSLATE_CONVERT_BIN2HEX);
         * yaguraConverterMenu.add(yaguraConverterBin2HexMenu);
         *
         * JMenuItem yaguraConverterHex2BinMenu = createMenuItem("hex2bin",
         * KeyEvent.VK_H, this.TRANSLATE_CONVERT_HEX2BIN);
         * yaguraConverterMenu.add(yaguraConverterHex2BinMenu);
         *
         * JMenuItem yaguraConverterFull2Half = createMenuItem("Full width ->
         * Half width", KeyEvent.VK_F, this.TRANSLATE_CONVERT_FULL2HALF);
         * yaguraConverterMenu.add(yaguraConverterFull2Half);
         *
         * JMenuItem yaguraConverterHalf2Full = createMenuItem("Half width ->
         * Full width", KeyEvent.VK_K, this.TRANSLATE_CONVERT_HALF2FULL);
         * yaguraConverterMenu.add(yaguraConverterHalf2Full);
***
         */
        yaguraMenu.add(yaguraConverterMenu);

        /**
         * Yagura Hash
         */
        JMenu yaguraHashMenu = new JMenu();
        yaguraHashMenu.setText("Hash (H)");
        yaguraHashMenu.setMnemonic(KeyEvent.VK_H);

        for (TranslateItemAction menuAction : MENU_HASH_ACTION) {
            yaguraHashMenu.add(createMenuItem(menuAction));
        }

        /**
         * **
         * JMenuItem yaguraHashMD2Menu = createMenuItem("md2", KeyEvent.VK_0,
         * this.TRANSLATE_HASH_MD2); yaguraHashMenu.add(yaguraHashMD2Menu);
         *
         * JMenuItem yaguraHashMD5Menu = createMenuItem("md5", KeyEvent.VK_1,
         * this.TRANSLATE_HASH_MD5); yaguraHashMenu.add(yaguraHashMD5Menu);
         *
         * JMenuItem yaguraHashSha1Menu = createMenuItem("sha1", KeyEvent.VK_2,
         * this.TRANSLATE_HASH_SHA1); yaguraHashMenu.add(yaguraHashSha1Menu);
         *
         * JMenuItem yaguraHashSha256Menu = createMenuItem("sha256",
         * KeyEvent.VK_3, this.TRANSLATE_HASH_SHA256);
         * yaguraHashMenu.add(yaguraHashSha256Menu);
         *
         * JMenuItem yaguraHashSha384Menu = createMenuItem("sha384",
         * KeyEvent.VK_4, this.TRANSLATE_HASH_SHA384);
         * yaguraHashMenu.add(yaguraHashSha384Menu);
         *
         * JMenuItem yaguraHashSha512Menu = createMenuItem("sha512",
         * KeyEvent.VK_5, this.TRANSLATE_HASH_SHA512);
         * yaguraHashMenu.add(yaguraHashSha512Menu);
***
         */
        yaguraMenu.add(yaguraHashMenu);

        /**
         * Yagura Result Filter
         */
        yaguraResultFilterMenu.setText("Result Filter (F)");
        yaguraResultFilterMenu.setMnemonic(KeyEvent.VK_F);
        yaguraResultFilterMenu.setEnabled(BurpConfig.isSupportApi(api, BurpConfig.SupportApi.BURPSUITE_BAMBDA));
//            updateResultFilterUI(this.yaguraResultFilterMenu);
        yaguraMenu.add(this.yaguraResultFilterMenu);

//        yaguraMenu.add(burpInterceptMenu);
        /**
         * Yagura Extension
         */
        JMenu yaguraExtensionMenu = new JMenu();
        yaguraExtensionMenu.setText("Extension (X)");
        yaguraExtensionMenu.setMnemonic(KeyEvent.VK_X);

        JMenuItem yaguraPasteIncludeTargetScopeMenu = createMenuItem("Paste include Target scope (multi-line)", KeyEvent.VK_I, this.INCLUDE_TARGET_SCOPE_ACTION);
        yaguraExtensionMenu.add(yaguraPasteIncludeTargetScopeMenu);

        JMenuItem yaguraPasteIncludeTopUrlScopeMenu = createMenuItem("Paste Root URL into include Target scope (multi-line)", KeyEvent.VK_R, this.INCLUDE_ROOTURL_TARGET_SCOPE_ACTION);
        yaguraExtensionMenu.add(yaguraPasteIncludeTopUrlScopeMenu);

        JMenuItem yaguraPasteExludeTargetScopeMenu = createMenuItem("Paste exclude Target scope (multi-line)", KeyEvent.VK_E, this.EXCLUDE_TARGET_SCOPE_ACTION);
        yaguraExtensionMenu.add(yaguraPasteExludeTargetScopeMenu);

        JMenuItem yaguraPasteSSLPassThroughMenu = createMenuItem("Paste SSL pass through (multi-line)", KeyEvent.VK_P, this.SSL_PASS_THROUGH_ACTION);
        yaguraExtensionMenu.add(yaguraPasteSSLPassThroughMenu);
        yaguraMenu.add(yaguraExtensionMenu);

        JMenuItem yaguraHostnameResolutionMenu = createMenuItem("Paste Hostname resolution (multi-line)", KeyEvent.VK_H, this.DNS_HOST_NAME_ACTION);
        yaguraExtensionMenu.add(yaguraHostnameResolutionMenu);
        yaguraMenu.add(yaguraExtensionMenu);

        /**
         * Burp Charsets
         */
        this.burpCharsetMenu.setText("Burp Charsets (B)");
        this.burpCharsetMenu.setMnemonic(KeyEvent.VK_B);
        this.burpCharsetMenu.setEnabled(BurpConfig.isSupportApi(api, BurpConfig.SupportApi.BURPSUITE_USEROPTION));
//            updateBurpCharsetUI(this.burpCharsetMenu);
        yaguraMenu.addSeparator();
        yaguraMenu.add(this.burpCharsetMenu);
        api.userInterface().menuBar().registerMenu(yaguraMenu);
    }

    /**
     * @param selectedText
     * @return the yaguraCharset
     */
    public String getYaguraCharset(String selectedText) {
        if (this.yaguraCharset != null) {
            return this.yaguraCharset;
        } else {
            if (BurpConfig.isSupportApi(this.api, BurpConfig.SupportApi.BURPSUITE_USEROPTION)) {
                BurpConfig.CharacterSets burpCharset = BurpConfig.getCharacterSets(api);
                if (BurpConfig.CharacterSetMode.PLATFORM_DEFAULT.toIdent().equals(burpCharset.getMode())) {
                    return StringUtil.DEFAULT_ENCODING;
                } else if (BurpConfig.CharacterSetMode.RAW_BYTES.toIdent().equals(burpCharset.getMode())) {
                    return StandardCharsets.ISO_8859_1.name();
                } else if (BurpConfig.CharacterSetMode.SPECIFIC_CHARACTER_SET.toIdent().equals(burpCharset.getMode())) {
                    return burpCharset.getCharacterSet();
                } else if (BurpConfig.CharacterSetMode.RECOGNIZE_AUTO.toIdent().equals(burpCharset.getMode())) {
                    return HttpUtil.getGuessCode(StringUtil.getBytesRaw(selectedText));
                }
            }
        }
        return StandardCharsets.ISO_8859_1.name();
    }

    public void setBamba(FilterProperty filter) {
        BurpConfig.configBambda(this.api, filter, true);
    }

    public static JMenuItem createMenuItem(String caption, int mnemonic, java.awt.event.ActionListener actionListener) {
        return createMenuItem(caption, mnemonic, null, actionListener);
    }

    public static JMenuItem createMenuItem(String caption, int mnemonic, String hotKey, java.awt.event.ActionListener actionListener) {
        JMenuItem yaguraMenuItem = new JMenuItem();
        if (mnemonic < 0) {
            yaguraMenuItem.setText(caption);
        } else {
            yaguraMenuItem.setText(caption + " (" + (char) mnemonic + ")");
            yaguraMenuItem.setMnemonic(mnemonic);
        }
        if (hotKey != null) {
            KeyStroke ks = BurpHotKey.parseKeyText(hotKey);
            if (BurpHotKey.isValid(ks)) {
                yaguraMenuItem.setAccelerator(ks);
            }
        }
        yaguraMenuItem.addActionListener(actionListener);
        return yaguraMenuItem;
    }

    public static JMenuItem createMenuItem(String caption, int mnemonic, BiFunction<String, String, String> action) {
        return createMenuItem(caption, mnemonic, new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                KeyboardFocusManager mgr = KeyboardFocusManager.getCurrentKeyboardFocusManager();
                Component owner = mgr.getPermanentFocusOwner();
                if (owner instanceof JTextArea textArea) {
                    String allText = textArea.getText();
                    String selectedText = textArea.getSelectedText();
                    String encode = action.apply(allText, selectedText);
                    if (encode != null) {
                        textArea.replaceSelection(encode);
                    }
                }
            }
        });
    }

    public JMenuItem createMenuItem(TranslateItemAction translate) {
        return createMenuItem(translate.getCaption(), translate.getMnemonic(), translate.getHotKey(), new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                KeyboardFocusManager mgr = KeyboardFocusManager.getCurrentKeyboardFocusManager();
                Component owner = mgr.getPermanentFocusOwner();
                if (owner instanceof JTextArea textArea) {
                    BiFunction<String, String, String> func = ACTION_MAP.get(translate.getAction());
                    if (func != null) {
                        String allText = textArea.getText();
                        String selectedText = textArea.getSelectedText();
                        String encode = func.apply(allText, selectedText);
                        if (encode != null) {
                            textArea.replaceSelection(encode);
                        }
                    }
                }
            }
        });
    }

    public String getYaguraSelectEncode() {
        ButtonModel model = this.menuYaguraCharsetsGroup.getSelection();
        String charset = model.getActionCommand();
        if (USE_BURP_CHARSETS.equals(charset)) {
            return null;
        } else {
            return charset;
        }
    }

    public void setYaguraSelectEncode(String encoding) {
        this.yaguraCharset = encoding;
        updateYaguraCharsetUI(this.yaguraCharsetMenu);
    }

    public boolean isYaguraConvertUpperCase() {
        return TransUtil.ConvertCase.UPPER.equals(getYaguraConvertCase());
    }

    public TransUtil.ConvertCase getYaguraConvertCase() {
        ButtonModel model = this.menuYaguraConvertCaseGroup.getSelection();
        TransUtil.ConvertCase convertCase = Enum.valueOf(TransUtil.ConvertCase.class, model.getActionCommand());
        return convertCase;
    }

    public TransUtil.EncodeType getYaguraEncodeType() {
        ButtonModel model = menuYaguraEncodeTypeGroup.getSelection();
        TransUtil.EncodeType encodeType = Enum.valueOf(TransUtil.EncodeType.class, model.getActionCommand());
        return encodeType;
    }

    public void setYaguraEncodeType(TransUtil.EncodeType encodeType) {
        for (Enumeration<AbstractButton> e = this.menuYaguraEncodeTypeGroup.getElements(); e.hasMoreElements();) {
            AbstractButton btn = e.nextElement();
            if (encodeType.name().equals(btn.getActionCommand())) {
                btn.setSelected(true);
                break;
            }
        }
    }

    public void updateUI() {
        updateYaguraCharsetUI(this.yaguraCharsetMenu);
        updateBurpCharsetUI(this.burpCharsetMenu);
        updateResultFilterUI(this.yaguraResultFilterMenu);
    }

    /**
     * Yagura Charset Menu
     */
    private void updateYaguraCharsetUI(JMenu yaguraCharsetMenu) {
        yaguraCharsetMenu.removeAll();
        for (Enumeration<AbstractButton> e = this.menuYaguraCharsetsGroup.getElements(); e.hasMoreElements();) {
            this.menuYaguraCharsetsGroup.remove(e.nextElement());
        }
        JRadioButtonMenuItem selectedYaguraCharSet = null;
        final List<String> encodngList = this.extenderImpl.getSelectEncodingList();
        for (int i = 0; i < encodngList.size(); i++) {
            JRadioButtonMenuItem specificCharsetMenuCharSet = new JRadioButtonMenuItem();
            specificCharsetMenuCharSet.setText(encodngList.get(i));
            specificCharsetMenuCharSet.setActionCommand(encodngList.get(i));
            if (this.yaguraCharset != null && this.yaguraCharset.equals(encodngList.get(i))) {
                selectedYaguraCharSet = specificCharsetMenuCharSet;
            }
            yaguraCharsetMenu.add(specificCharsetMenuCharSet);
            this.menuYaguraCharsetsGroup.add(specificCharsetMenuCharSet);
        }

        // Use Burp Charsets
        yaguraCharsetMenu.addSeparator();
        JRadioButtonMenuItem useBurpCharSet = new JRadioButtonMenuItem();
        useBurpCharSet.setText(USE_BURP_CHARSETS);
        useBurpCharSet.setActionCommand(USE_BURP_CHARSETS);
        if (this.yaguraCharset == null) {
            selectedYaguraCharSet = useBurpCharSet;
        }
        useBurpCharSet.setEnabled(BurpConfig.isSupportApi(this.api, BurpConfig.SupportApi.BURPSUITE_USEROPTION));
        yaguraCharsetMenu.add(useBurpCharSet);
        this.menuYaguraCharsetsGroup.add(useBurpCharSet);

        // Yagura Charset 選択状態
        if (selectedYaguraCharSet != null) {
            this.menuYaguraCharsetsGroup.setSelected(selectedYaguraCharSet.getModel(), true);
        } else {
            this.menuYaguraCharsetsGroup.setSelected(useBurpCharSet.getModel(), true);
        }
        Enumeration<AbstractButton> emu = this.menuYaguraCharsetsGroup.getElements();
        while (emu.hasMoreElements()) {
            if (emu.nextElement() instanceof JRadioButtonMenuItem yaguraCharsetMenuItem) {
                yaguraCharsetMenuItem.addActionListener(this.YAGURA_CHARSET_ACTION);
                yaguraCharsetMenuItem.addChangeListener(this.YAGURA_CHARSET_CHANGE_ACTION);
            }
        }
    }

    /**
     * Burp Charsets
     */
    private void updateBurpCharsetUI(JMenu burpCharsetMenu) {
        burpCharsetMenu.removeAll();
        for (Enumeration<AbstractButton> e = this.menuBurpCharsetsGroup.getElements(); e.hasMoreElements();) {
            this.menuBurpCharsetsGroup.remove(e.nextElement());
        }
        if (!BurpConfig.isSupportApi(this.api, BurpConfig.SupportApi.BURPSUITE_USEROPTION)) {
            return;
        }
        JRadioButtonMenuItem selectedBurpCharSet = null;
        BurpConfig.CharacterSets burpCharset = BurpConfig.getCharacterSets(api);
        if (burpCharset.getCharacterSet() == null) {
            burpCharset.setCharacterSet(StandardCharsets.UTF_8.name());
        }

        JRadioButtonMenuItem burpCharsetItemMenuAuto = new JRadioButtonMenuItem();
        burpCharsetItemMenuAuto.setText(BurpConfig.CharacterSetMode.RECOGNIZE_AUTO.toIdent());
        burpCharsetMenu.add(burpCharsetItemMenuAuto);
        this.menuBurpCharsetsGroup.add(burpCharsetItemMenuAuto);
        if (BurpConfig.CharacterSetMode.RECOGNIZE_AUTO.toIdent().equals(burpCharset.getMode())) {
            selectedBurpCharSet = burpCharsetItemMenuAuto;
        }

        JRadioButtonMenuItem burpCharsetItemMenuDefault = new JRadioButtonMenuItem();
        burpCharsetItemMenuDefault.setText(BurpConfig.CharacterSetMode.PLATFORM_DEFAULT.toIdent());
        burpCharsetMenu.add(burpCharsetItemMenuDefault);
        this.menuBurpCharsetsGroup.add(burpCharsetItemMenuDefault);
        if (BurpConfig.CharacterSetMode.PLATFORM_DEFAULT.toIdent().equals(burpCharset.getMode())) {
            selectedBurpCharSet = burpCharsetItemMenuDefault;
        }

        JRadioButtonMenuItem burpCharsetItemMenuRaw = new JRadioButtonMenuItem();
        burpCharsetItemMenuRaw.setText(BurpConfig.CharacterSetMode.RAW_BYTES.toIdent());
        burpCharsetMenu.add(burpCharsetItemMenuRaw);
        this.menuBurpCharsetsGroup.add(burpCharsetItemMenuRaw);
        if (BurpConfig.CharacterSetMode.RAW_BYTES.toIdent().equals(burpCharset.getMode())) {
            selectedBurpCharSet = burpCharsetItemMenuRaw;
        }

        burpCharsetMenu.addSeparator();

        final List<String> encodngList = extenderImpl.getSelectEncodingList();
        for (int i = 0; i < encodngList.size(); i++) {
            JRadioButtonMenuItem specificCharsetMenuCharSet = new JRadioButtonMenuItem();
            specificCharsetMenuCharSet.setText(encodngList.get(i));
            if (BurpConfig.CharacterSetMode.SPECIFIC_CHARACTER_SET.toIdent().equals(burpCharset.getMode()) && burpCharset.getCharacterSet().equals(encodngList.get(i))) {
                selectedBurpCharSet = specificCharsetMenuCharSet;
            }
            burpCharsetMenu.add(specificCharsetMenuCharSet);
            this.menuBurpCharsetsGroup.add(specificCharsetMenuCharSet);
        }

        // Burp Charset 選択状態
        if (selectedBurpCharSet != null) {
            this.menuBurpCharsetsGroup.setSelected(selectedBurpCharSet.getModel(), true);
        }
        Enumeration<AbstractButton> emu = this.menuBurpCharsetsGroup.getElements();
        while (emu.hasMoreElements()) {
            if (emu.nextElement() instanceof JRadioButtonMenuItem burpCharsetMenuItem) {
                burpCharsetMenuItem.addActionListener(this.BURP_CHARSETMODE_MODE_ACTION);
            }
        }
    }

    /**
     * Burp Intercept
     */
    private void updateInterceptUI(JMenu burpInterceptMenu) {
        BurpConfig.InterceptClientRequests burpInterceptRequest = BurpConfig.getInterceptClientRequests(this.api);
        BurpConfig.InterceptServerResponses burpInterceptResponse = BurpConfig.getInterceptServerResponses(this.api);
        BurpConfig.InterceptWebSocketsMessages burpInterceptWs = BurpConfig.getInterceptWebSocketsMessages(this.api);
    }

    /**
     * Result Filter
     */
    private void updateResultFilterUI(JMenu yaguraResultFilterMenu) {
        boolean supportBanmbaSiteMap = BurpConfig.isSupportApi(api, BurpConfig.SupportApi.BURPSUITE_BAMBDA_SITEMAP);

        yaguraResultFilterMenu.removeAll();
        final Map<String, FilterProperty> filterMap = extenderImpl.getProperty().getResultFilterProperty().getFilterMap();
        for (Map.Entry<String, FilterProperty> entry : filterMap.entrySet()) {
            String name = entry.getKey();
            FilterProperty filter = entry.getValue();
            JMenuItem mnuResultFilterItem = new JMenuItem();
            mnuResultFilterItem.setIcon(ResultFilterDlg.getCategoryIcon(filter.getFilterCategory()));
            mnuResultFilterItem.setText(name);
            mnuResultFilterItem.addActionListener(this.RESULTFILTER_MODE_ACTION);
            if (filter.getFilterCategory() == FilterProperty.FilterCategory.SITE_MAP) {
                mnuResultFilterItem.setEnabled(supportBanmbaSiteMap);
            }
            yaguraResultFilterMenu.add(mnuResultFilterItem);
            // this.menuBurpResultFilterGroup.add(chkResultFilterItem);
        }
    }

    /**
     * Yagura Charsets
     */
    private final java.awt.event.ActionListener YAGURA_CHARSET_ACTION = new java.awt.event.ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            if (e.getSource() instanceof JRadioButtonMenuItem item) {
                extenderImpl.getProperty().getYaguraProperty().setSelectEncoding(getYaguraSelectEncode());
                extenderImpl.applyOptionProperty();
            }
        }
    };

    private final ChangeListener YAGURA_CHARSET_CHANGE_ACTION = new ChangeListener() {

        @Override
        public void stateChanged(ChangeEvent e) {
            if (e.getSource() instanceof JRadioButtonMenuItem item) {
                if (item.isSelected()) {
                    String caption = item.getText();
                    if (USE_BURP_CHARSETS.equals(caption)) {
                        yaguraCharset = null;
                    } else {
                        yaguraCharset = caption;
                    }
                }
            }
        }
    };

    /**
     * Yagura Encode Tyoe
     */
    private final java.awt.event.ActionListener YAGURA_CONVERT_CASE_ACTION = new java.awt.event.ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            extenderImpl.getProperty().getYaguraProperty().setConvertCase(getYaguraConvertCase());
            extenderImpl.applyOptionProperty();
        }
    };

    private final java.awt.event.ActionListener YAGURA_ENCODE_TYPE_ACTION = new java.awt.event.ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            extenderImpl.getProperty().getYaguraProperty().setEncodeType(getYaguraEncodeType());
            extenderImpl.applyOptionProperty();
        }
    };

    /**
     * Encoder
     */
    private final BiFunction TRANSLATE_ENCODE_URL = new BiFunction<String, String, String>() {
        @Override
        public String apply(String allText, String selectedText) {
            try {
                return SmartCodec.toUrlEncode(selectedText, getYaguraCharset(selectedText), TransUtil.getEncodeTypePattern(getYaguraEncodeType()), isYaguraConvertUpperCase());
            } catch (UnsupportedEncodingException ex) {
                return selectedText;
            }
        }
    };

    private final BiFunction TRANSLATE_ENCODE_UNICODE_URL = new BiFunction<String, String, String>() {
        @Override
        public String apply(String allText, String selectedText) {
            return SmartCodec.toUnicodeUrlEncode(selectedText, TransUtil.getEncodeTypePattern(getYaguraEncodeType()), isYaguraConvertUpperCase());
        }
    };

    private final BiFunction TRANSLATE_ENCODE_UNICODE_JSON = new BiFunction<String, String, String>() {
        @Override
        public String apply(String allText, String selectedText) {
            return SmartCodec.toUnicodeEncode(selectedText, TransUtil.getEncodeTypePattern(getYaguraEncodeType()), isYaguraConvertUpperCase());
        }
    };

    private final BiFunction TRANSLATE_ENCODE_BASE64 = new BiFunction<String, String, String>() {
        @Override
        public String apply(String allText, String selectedText) {
            try {
                return CodecUtil.toBase64Encode(selectedText, getYaguraCharset(selectedText));
            } catch (UnsupportedEncodingException ex) {
                return selectedText;
            }
        }
    };

    private final BiFunction TRANSLATE_ENCODE_BASE64_SAFE = new BiFunction<String, String, String>() {
        @Override
        public String apply(String allText, String selectedText) {
            try {
                return CodecUtil.toBase64URLSafeEncode(selectedText, getYaguraCharset(selectedText));
            } catch (UnsupportedEncodingException ex) {
                return selectedText;
            }
        }
    };

    private final BiFunction TRANSLATE_ENCODE_BASE64_URL = new BiFunction<String, String, String>() {
        @Override
        public String apply(String allText, String selectedText) {
            try {
                return SmartCodec.toUrlEncode(CodecUtil.toBase64Encode(selectedText, getYaguraCharset(selectedText)), StandardCharsets.US_ASCII, TransUtil.getEncodeTypePattern(getYaguraEncodeType()), isYaguraConvertUpperCase());
            } catch (UnsupportedEncodingException ex) {
                return selectedText;
            }
        }
    };

    private final BiFunction TRANSLATE_ENCODE_HTML = new BiFunction<String, String, String>() {
        @Override
        public String apply(String allText, String selectedText) {
            return SmartCodec.toHtmlDecEncode(selectedText, TransUtil.getEncodeTypePattern(getYaguraEncodeType()));
        }
    };

    private final BiFunction TRANSLATE_ENCODE_JSON_META = new BiFunction<String, String, String>() {
        @Override
        public String apply(String allText, String selectedText) {
            return ConvertUtil.encodeJsonLiteral(selectedText, true);
        }
    };

    /**
     * Decoder
     */
    private final BiFunction TRANSLATE_DECODE_URL = new BiFunction<String, String, String>() {
        @Override
        public String apply(String allText, String selectedText) {
            try {
                return SmartCodec.toUrlDecode(selectedText, getYaguraCharset(selectedText));
            } catch (UnsupportedEncodingException ex) {
                return selectedText;
            }
        }
    };

    private final BiFunction TRANSLATE_DECODE_UNICODE_URL = new BiFunction<String, String, String>() {
        @Override
        public String apply(String allText, String selectedText) {
            return SmartCodec.toUnicodeUrlDecode(selectedText);
        }
    };

    private final BiFunction TRANSLATE_DECODE_UNICODE_JSON = new BiFunction<String, String, String>() {
        @Override
        public String apply(String allText, String selectedText) {
            return SmartCodec.toUnocodeDecode(selectedText);
        }
    };

    private final BiFunction TRANSLATE_DECODE_BASE64 = new BiFunction<String, String, String>() {
        @Override
        public String apply(String allText, String selectedText) {
            try {
                return CodecUtil.toBase64Decode(selectedText, getYaguraCharset(selectedText));
            } catch (UnsupportedEncodingException ex) {
                return selectedText;
            }
        }
    };

    private final BiFunction TRANSLATE_DECODE_BASE64_SAFE = new BiFunction<String, String, String>() {
        @Override
        public String apply(String allText, String selectedText) {
            try {
                return CodecUtil.toBase64URLSafeDecode(selectedText, getYaguraCharset(selectedText));
            } catch (UnsupportedEncodingException ex) {
                return selectedText;
            }
        }
    };

    private final BiFunction TRANSLATE_DECODE_BASE64_URL = new BiFunction<String, String, String>() {
        @Override
        public String apply(String allText, String selectedText) {
            try {
                return CodecUtil.toBase64Decode(SmartCodec.toUrlDecode(selectedText, StandardCharsets.US_ASCII), getYaguraCharset(selectedText));
            } catch (UnsupportedEncodingException ex) {
                return selectedText;
            }
        }
    };

    private final BiFunction TRANSLATE_DECODE_HTML = new BiFunction<String, String, String>() {
        @Override
        public String apply(String allText, String selectedText) {
            return SmartCodec.toHtmlDecode(selectedText, TransUtil.getEncodeTypePattern(getYaguraEncodeType()));
        }
    };

    private final BiFunction TRANSLATE_DECODE_JSON_META = new BiFunction<String, String, String>() {
        @Override
        public String apply(String allText, String selectedText) {
            return ConvertUtil.decodeJsonLiteral(selectedText, true);
        }
    };

    /**
     * Converter
     */
    private final BiFunction TRANSLATE_CONVERT_UPPER_CASE = new BiFunction<String, String, String>() {
        @Override
        public String apply(String allText, String selectedText) {
            return selectedText.toUpperCase();
        }
    };

    private final BiFunction TRANSLATE_CONVERT_LOWLER_CASE = new BiFunction<String, String, String>() {
        @Override
        public String apply(String allText, String selectedText) {
            return selectedText.toLowerCase();
        }
    };

    private final BiFunction TRANSLATE_CONVERT_BIN2HEX = new BiFunction<String, String, String>() {
        @Override
        public String apply(String allText, String selectedText) {
            try {
                return TransUtil.toByteHexEncode(selectedText, getYaguraCharset(selectedText), false);
            } catch (UnsupportedEncodingException ex) {
                return selectedText;
            }
        }
    };

    private final BiFunction TRANSLATE_CONVERT_HEX2BIN = new BiFunction<String, String, String>() {
        @Override
        public String apply(String allText, String selectedText) {
            try {
                return TransUtil.toByteHexDecode(selectedText, getYaguraCharset(selectedText));
            } catch (UnsupportedEncodingException ex) {
                return selectedText;
            }
        }
    };

    private final BiFunction TRANSLATE_CONVERT_FULL2HALF = new BiFunction<String, String, String>() {
        @Override
        public String apply(String allText, String selectedText) {
            return TransUtil.translateFullWidth2HalfWidth(selectedText);
        }
    };

    private final BiFunction TRANSLATE_CONVERT_HALF2FULL = new BiFunction<String, String, String>() {
        @Override
        public String apply(String allText, String selectedText) {
            return TransUtil.translateHalfWidth2FullWidth(selectedText);
        }
    };

    /**
     * Hash
     */
    private final BiFunction TRANSLATE_HASH_MD2 = new BiFunction<String, String, String>() {
        @Override
        public String apply(String allText, String selectedText) {
            try {
                return BouncyUtil.toMD2Sum(selectedText, getYaguraCharset(selectedText), isYaguraConvertUpperCase());
            } catch (UnsupportedEncodingException ex) {
                return selectedText;
            }
        }
    };

    private final BiFunction TRANSLATE_HASH_MD5 = new BiFunction<String, String, String>() {
        @Override
        public String apply(String allText, String selectedText) {
            try {
                return BouncyUtil.toMD5Sum(selectedText, getYaguraCharset(selectedText), isYaguraConvertUpperCase());
            } catch (UnsupportedEncodingException ex) {
                return selectedText;
            }
        }
    };

    private final BiFunction TRANSLATE_HASH_SHA1 = new BiFunction<String, String, String>() {
        @Override
        public String apply(String allText, String selectedText) {
            try {
                return BouncyUtil.toSHA1Sum(selectedText, getYaguraCharset(selectedText), isYaguraConvertUpperCase());
            } catch (UnsupportedEncodingException ex) {
                return selectedText;
            }
        }
    };

    private final BiFunction TRANSLATE_HASH_SHA256 = new BiFunction<String, String, String>() {
        @Override
        public String apply(String allText, String selectedText) {
            try {
                return BouncyUtil.toSHA256Sum(selectedText, getYaguraCharset(selectedText), isYaguraConvertUpperCase());
            } catch (UnsupportedEncodingException ex) {
                return selectedText;
            }
        }
    };

    private final BiFunction TRANSLATE_HASH_SHA384 = new BiFunction<String, String, String>() {
        @Override
        public String apply(String allText, String selectedText) {
            try {
                return BouncyUtil.toSHA384Sum(selectedText, getYaguraCharset(selectedText), isYaguraConvertUpperCase());
            } catch (UnsupportedEncodingException ex) {
                return selectedText;
            }
        }
    };

    private final BiFunction TRANSLATE_HASH_SHA512 = new BiFunction<String, String, String>() {
        @Override
        public String apply(String allText, String selectedText) {
            try {
                return BouncyUtil.toSHA512Sum(selectedText, getYaguraCharset(selectedText), isYaguraConvertUpperCase());
            } catch (UnsupportedEncodingException ex) {
                return selectedText;
            }
        }
    };

    private final java.awt.event.ActionListener RESULTFILTER_MODE_ACTION = new java.awt.event.ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            ResultFilterProperty resultFilterProperty = extenderImpl.getProperty().getResultFilterProperty();
            Map<String, FilterProperty> filterMap = resultFilterProperty.getFilterMap();
            FilterProperty filterProperty = null;
            if (e.getSource() instanceof JMenuItem menuItem) {
                String selectedName = menuItem.getText();
                filterProperty = filterMap.get(selectedName);
                if (filterProperty != null) {
                    resultFilterProperty.setSelectedName(selectedName);
                    BurpConfig.configBambda(api, filterProperty, true);
                    IBurpTab tab = extenderImpl.getRootTabComponent();
                    BurpUtil.flashTab(tab, "Proxy");
                }
            }
        }
    };

    private final java.awt.event.ActionListener INCLUDE_SCOPE_ACTION = new java.awt.event.ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            try {
                String paste = SwingUtil.systemClipboardPaste();
                BurpExtension.helpers().addIncludeScope(paste);
            } catch (Exception ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
    };

    private final java.awt.event.ActionListener INCLUDE_HOST_SCOPE_ACTION = new java.awt.event.ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            try {
                String paste = SwingUtil.systemClipboardPaste();
                URI uri = URI.create(paste);
                URL url = uri.toURL();
                BurpExtension.helpers().addIncludeScope(String.format("%s://%s/", url.getProtocol(), HttpUtil.buildHost(url.getHost(), url.getPort(), url.getProtocol())));
            } catch (MalformedURLException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
    };

    /**
     * Extension
     */
    private final java.awt.event.ActionListener INCLUDE_TARGET_SCOPE_ACTION = new java.awt.event.ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            try {
                String paste = SwingUtil.systemClipboardPaste();
                BurpExtension.helpers().addIncludeTargetScope(paste, false);
                IBurpTab tab = extenderImpl.getRootTabComponent();
                BurpUtil.flashTab(tab, "Target");
            } catch (Exception ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
    };

    private final java.awt.event.ActionListener INCLUDE_ROOTURL_TARGET_SCOPE_ACTION = new java.awt.event.ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            try {
                String paste = SwingUtil.systemClipboardPaste();
                BurpExtension.helpers().addIncludeRootURLTargetScope(paste, false);
                IBurpTab tab = extenderImpl.getRootTabComponent();
                BurpUtil.flashTab(tab, "Target");
            } catch (Exception ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
    };

    private final java.awt.event.ActionListener EXCLUDE_SCOPE_ACTION = new java.awt.event.ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            try {
                String paste = SwingUtil.systemClipboardPaste();
                BurpExtension.helpers().addExcludeScope(paste);
            } catch (Exception ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
    };

    private final java.awt.event.ActionListener EXCLUDE_TARGET_SCOPE_ACTION = new java.awt.event.ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            try {
                String paste = SwingUtil.systemClipboardPaste();
                BurpExtension.helpers().addExcludeTargetScope(paste, false);
                IBurpTab tab = extenderImpl.getRootTabComponent();
                BurpUtil.flashTab(tab, "Target");
            } catch (Exception ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
    };

    private final java.awt.event.ActionListener SSL_PASS_THROUGH_ACTION = new java.awt.event.ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            try {
                String paste = SwingUtil.systemClipboardPaste();
                URL[] urls = TargetScopeItem.parseMultilineURL(paste);
                List<BurpConfig.SSLPassThroughRule> rules = new ArrayList<>();
                for (URL u : urls) {
                    int port = u.getPort() > 0 ? u.getPort() : u.getDefaultPort();
                    rules.add(new BurpConfig.SSLPassThroughRule(true, BurpUtil.escapeRegex(u.getHost()), BurpUtil.escapeRegex(StringUtil.toString(port))));
                }
                BurpConfig.configSSLPassThroughRules(api, rules, false);
                IBurpTab tab = extenderImpl.getRootTabComponent();
                BurpUtil.flashTab(tab, "Proxy");
            } catch (Exception ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
    };

    private final java.awt.event.ActionListener DNS_HOST_NAME_ACTION = new java.awt.event.ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            try {
                String paste = SwingUtil.systemClipboardPaste();
                Stream<String> hostlines = HostName.parseHostLines(paste);
                HostName hostName = HostName.parseHosts(hostlines);
                List<BurpConfig.HostnameResolution> hosts = new ArrayList<>();
                for (HostNameEntry hostEntry : hostName.getHostNameEntry()) {
                    if (hostEntry.isValidIP()) {
                        hosts.add(new BurpConfig.HostnameResolution(true, hostEntry.getHostName(), hostEntry.getIPAddress()));
                    }
                }
                BurpConfig.configHostnameResolution(api, hosts);
            } catch (Exception ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
    };

    /**
     * Burp Charsets
     */
    private final java.awt.event.ActionListener BURP_CHARSETMODE_MODE_ACTION = new java.awt.event.ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            final List<String> encodngList = extenderImpl.getSelectEncodingList();
            BurpConfig.CharacterSets burpCharset = BurpConfig.getCharacterSets(BurpConfig.CharacterSetMode.SPECIFIC_CHARACTER_SET, StandardCharsets.UTF_8.name());
            Enumeration<AbstractButton> rdoCharsets = menuBurpCharsetsGroup.getElements();
            while (rdoCharsets.hasMoreElements()) {
                JRadioButtonMenuItem item = (JRadioButtonMenuItem) rdoCharsets.nextElement();
                if (item.isSelected()) {
                    if (encodngList.contains(item.getText())) {
                        burpCharset.setMode(BurpConfig.CharacterSetMode.SPECIFIC_CHARACTER_SET.toIdent());
                        burpCharset.setCharacterSet(item.getText());
                    } else {
                        burpCharset.setMode(item.getText());
                    }
                    break;
                }
            }
            BurpConfig.configCharacterSets(api, burpCharset);
        }
    };

    public final static TranslateItemAction MENU_ENCODE_ACTION[] = {
        new TranslateItemAction("URL(%hh)", KeyEvent.VK_U, null, TranslateItemAction.TranslateAction.ENCODE_URL), // KeyStroke.getKeyStroke(KeyEvent.VK_U, InputEvent.CTRL_DOWN_MASK | InputEvent.ALT_DOWN_MASK)
        new TranslateItemAction("Unicode(%uhhhh) - URL", KeyEvent.VK_N, null, TranslateItemAction.TranslateAction.ENCODE_UNICODE_URL),
        new TranslateItemAction("Unicode(\\uhhhh) - JSON", KeyEvent.VK_J, null, TranslateItemAction.TranslateAction.ENCODE_UNICODE_JSON),
        new TranslateItemAction("Base64", KeyEvent.VK_B, null, TranslateItemAction.TranslateAction.ENCODE_BASE64), // KeyStroke.getKeyStroke(KeyEvent.VK_B, InputEvent.CTRL_DOWN_MASK | InputEvent.ALT_DOWN_MASK)
        new TranslateItemAction("Base64URLSafe", KeyEvent.VK_S, null, TranslateItemAction.TranslateAction.ENCODE_BASE64_SAFE),
        new TranslateItemAction("Base64 + URL", KeyEvent.VK_A, null, TranslateItemAction.TranslateAction.ENCODE_BASE64_URL),
        new TranslateItemAction("Html", KeyEvent.VK_A, null, TranslateItemAction.TranslateAction.ENCODE_HTML), // KeyStroke.getKeyStroke(KeyEvent.VK_H, InputEvent.CTRL_DOWN_MASK | InputEvent.ALT_DOWN_MASK)
        new TranslateItemAction("JSON with Meta", KeyEvent.VK_M, null, TranslateItemAction.TranslateAction.ENCODE_JSON_META)
    };

    public final static TranslateItemAction MENU_DECODER_ACTION[] = {
        new TranslateItemAction("URL(%hh)", KeyEvent.VK_U, null, TranslateItemAction.TranslateAction.DECODE_URL), // KeyStroke.getKeyStroke(KeyEvent.VK_U, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK | InputEvent.ALT_DOWN_MASK)
        new TranslateItemAction("Unicode(%uhhhh) - URL", KeyEvent.VK_N, null, TranslateItemAction.TranslateAction.DECODE_UNICODE_URL),
        new TranslateItemAction("Unicode(\\uhhhh) - JSON", KeyEvent.VK_J, null, TranslateItemAction.TranslateAction.DECODE_UNICODE_JSON),
        new TranslateItemAction("Base64", KeyEvent.VK_B, null, TranslateItemAction.TranslateAction.DECODE_BASE64), // KeyStroke.getKeyStroke(KeyEvent.VK_B, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK | InputEvent.ALT_DOWN_MASK)
        new TranslateItemAction("Base64URLSafe", KeyEvent.VK_S, null, TranslateItemAction.TranslateAction.DECODE_BASE64_SAFE),
        new TranslateItemAction("Base64 + URL", KeyEvent.VK_A, null, TranslateItemAction.TranslateAction.DECODE_BASE64_URL),
        new TranslateItemAction("Html", KeyEvent.VK_A, null, TranslateItemAction.TranslateAction.DECODE_HTML), // KeyStroke.getKeyStroke(KeyEvent.VK_H, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK | InputEvent.ALT_DOWN_MASK)
        new TranslateItemAction("JSON with Meta", KeyEvent.VK_M, null, TranslateItemAction.TranslateAction.DECODE_JSON_META)
    };

    public final static TranslateItemAction MENU_CONVERT_ACTION[] = {
        new TranslateItemAction("Upper Case", KeyEvent.VK_U, null, TranslateItemAction.TranslateAction.CONVERT_UPPER_CASE),
        new TranslateItemAction("Lowler Case", KeyEvent.VK_L, null, TranslateItemAction.TranslateAction.CONVERT_LOWLER_CASE),
        new TranslateItemAction("bin2hex", KeyEvent.VK_B, null, TranslateItemAction.TranslateAction.CONVERT_BIN2HEX),
        new TranslateItemAction("hex2bin", KeyEvent.VK_H, null, TranslateItemAction.TranslateAction.CONVERT_HEX2BIN),
        new TranslateItemAction("Full width -> Half width", KeyEvent.VK_F, null, TranslateItemAction.TranslateAction.CONVERT_FULL2HALF),
        new TranslateItemAction("Half width -> Full width", KeyEvent.VK_K, null, TranslateItemAction.TranslateAction.CONVERT_HALF2FULL)
    };

    public final static TranslateItemAction MENU_HASH_ACTION[] = {
        new TranslateItemAction("md2", KeyEvent.VK_0, null, TranslateItemAction.TranslateAction.HASH_MD2),
        new TranslateItemAction("md5", KeyEvent.VK_1, null, TranslateItemAction.TranslateAction.HASH_MD5),
        new TranslateItemAction("sha1", KeyEvent.VK_2, null, TranslateItemAction.TranslateAction.HASH_SHA1),
        new TranslateItemAction("sha256", KeyEvent.VK_3, null, TranslateItemAction.TranslateAction.HASH_SHA256),
        new TranslateItemAction("sha384", KeyEvent.VK_4, null, TranslateItemAction.TranslateAction.HASH_SHA384),
        new TranslateItemAction("sha512", KeyEvent.VK_5, null, TranslateItemAction.TranslateAction.HASH_SHA512)
    };

    private final Map<TranslateItemAction.TranslateAction, BiFunction<String, String, String>> ACTION_MAP = new HashMap<>() {
        {
            /* Encode */
            put(TranslateItemAction.TranslateAction.ENCODE_URL, TRANSLATE_ENCODE_URL);
            put(TranslateItemAction.TranslateAction.ENCODE_UNICODE_URL, TRANSLATE_ENCODE_UNICODE_URL);
            put(TranslateItemAction.TranslateAction.ENCODE_UNICODE_JSON, TRANSLATE_ENCODE_UNICODE_JSON);
            put(TranslateItemAction.TranslateAction.ENCODE_BASE64, TRANSLATE_ENCODE_BASE64);
            put(TranslateItemAction.TranslateAction.ENCODE_BASE64_SAFE, TRANSLATE_ENCODE_BASE64_SAFE);
            put(TranslateItemAction.TranslateAction.ENCODE_BASE64_URL, TRANSLATE_ENCODE_BASE64_URL);
            put(TranslateItemAction.TranslateAction.ENCODE_HTML, TRANSLATE_ENCODE_HTML);
            put(TranslateItemAction.TranslateAction.ENCODE_JSON_META, TRANSLATE_ENCODE_JSON_META);
            /* Decode */
            put(TranslateItemAction.TranslateAction.DECODE_URL, TRANSLATE_DECODE_URL);
            put(TranslateItemAction.TranslateAction.DECODE_UNICODE_URL, TRANSLATE_DECODE_UNICODE_URL);
            put(TranslateItemAction.TranslateAction.DECODE_UNICODE_JSON, TRANSLATE_DECODE_UNICODE_JSON);
            put(TranslateItemAction.TranslateAction.DECODE_BASE64, TRANSLATE_DECODE_BASE64);
            put(TranslateItemAction.TranslateAction.DECODE_BASE64_SAFE, TRANSLATE_DECODE_BASE64_SAFE);
            put(TranslateItemAction.TranslateAction.DECODE_BASE64_URL, TRANSLATE_DECODE_BASE64_URL);
            put(TranslateItemAction.TranslateAction.DECODE_HTML, TRANSLATE_DECODE_HTML);
            put(TranslateItemAction.TranslateAction.DECODE_JSON_META, TRANSLATE_DECODE_JSON_META);
            /* Convert */
            put(TranslateItemAction.TranslateAction.CONVERT_UPPER_CASE, TRANSLATE_CONVERT_UPPER_CASE);
            put(TranslateItemAction.TranslateAction.CONVERT_LOWLER_CASE, TRANSLATE_CONVERT_LOWLER_CASE);
            put(TranslateItemAction.TranslateAction.CONVERT_BIN2HEX, TRANSLATE_CONVERT_BIN2HEX);
            put(TranslateItemAction.TranslateAction.CONVERT_HEX2BIN, TRANSLATE_CONVERT_HEX2BIN);
            put(TranslateItemAction.TranslateAction.CONVERT_FULL2HALF, TRANSLATE_CONVERT_FULL2HALF);
            put(TranslateItemAction.TranslateAction.CONVERT_HALF2FULL, TRANSLATE_CONVERT_HALF2FULL);
            /* Hash */
            put(TranslateItemAction.TranslateAction.HASH_MD2, TRANSLATE_HASH_MD2);
            put(TranslateItemAction.TranslateAction.HASH_MD5, TRANSLATE_HASH_MD5);
            put(TranslateItemAction.TranslateAction.HASH_SHA1, TRANSLATE_HASH_SHA1);
            put(TranslateItemAction.TranslateAction.HASH_SHA256, TRANSLATE_HASH_SHA256);
            put(TranslateItemAction.TranslateAction.HASH_SHA384, TRANSLATE_HASH_SHA384);
            put(TranslateItemAction.TranslateAction.HASH_SHA512, TRANSLATE_HASH_SHA512);
        }
    };

    public static void changeContextMenuLevel(JMenuItem sendToPlaceMenu, SendToMenuPlace sendToMenuLevel) {
        sendToPlaceMenu.addHierarchyListener(new HierarchyListener() {
            private boolean changeFlag1 = false;

            @Override
            public void hierarchyChanged(HierarchyEvent e) {
                if ((e.getChangeFlags() & HierarchyEvent.PARENT_CHANGED) != 0) {
                    if (changeFlag1) {
                        return;
                    }
                    changeFlag1 = true;
                    if (sendToPlaceMenu.getParent() instanceof JPopupMenu popupMenu) {
                        // Extension
                        if (popupMenu.getInvoker() instanceof JMenuItem extensionNameMenuItem) {
                            extensionNameMenuItem.remove(sendToPlaceMenu);
                            extensionNameMenuItem.addHierarchyListener(new ExtensionMenuChangeListener(extensionNameMenuItem, sendToMenuLevel));
                        }
                    }
                }
            }
        });
    }

    protected static class ExtensionMenuChangeListener implements HierarchyListener {

        final SendToMenuPlace sendToMenuPlace;
        final JMenuItem extensionNameMenuItem;

        public ExtensionMenuChangeListener(JMenuItem extensionNameMenuItem, SendToMenuPlace sendToMenuPlace) {
            this.sendToMenuPlace = sendToMenuPlace;
            this.extensionNameMenuItem = extensionNameMenuItem;
        }

        private boolean changeFlag2 = false;

        @Override
        public void hierarchyChanged(HierarchyEvent e) {
            if ((e.getChangeFlags() & HierarchyEvent.PARENT_CHANGED) != 0) {
                if (changeFlag2) {
                    return;
                }
                changeFlag2 = true;
                if (this.extensionNameMenuItem.getParent() instanceof JPopupMenu extensionsPopupMenu) {
                    if (extensionsPopupMenu.getInvoker() instanceof JMenuItem extensionsMenuItem) {
                        if (!extensionsMenuItem.getText().equals("Extensions")) {
                            return;
                        }

                        extensionsMenuItem.addHierarchyListener(new HierarchyListener() {
                            private boolean changeFlag3 = false;

                            @Override
                            public void hierarchyChanged(HierarchyEvent e) {
                                if ((e.getChangeFlags() & HierarchyEvent.PARENT_CHANGED) != 0) {
                                    if (changeFlag3) {
                                        return;
                                    }
                                    changeFlag3 = true;

                                    if (sendToMenuPlace == SendToMenuPlace.TOP_LEVEL) {
                                        extensionsPopupMenu.remove(extensionNameMenuItem);  //　

                                        // TopLevel Menu
                                        if (extensionsMenuItem.getParent() instanceof JPopupMenu topLevelPopupMenu) {
                                            int index = topLevelPopupMenu.getComponentIndex(extensionsMenuItem) + 1;
                                            topLevelPopupMenu.add(extensionNameMenuItem, index);
                                        }
                                    }
                                }
                            }
                        });
                    }
                }
            }
        }
    }

}
