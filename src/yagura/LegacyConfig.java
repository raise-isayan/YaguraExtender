package yagura;

import yagura.model.AutoResponderItem;
import yagura.model.UniversalViewProperty;
import yagura.model.LoggingProperty;
import yagura.model.MatchAlertItem;
import extend.view.base.MatchItem;
import yagura.model.MatchReplaceItem;
import yagura.model.SendToItem;
import extend.util.HttpUtil;
import extend.util.IniProp;
import extend.util.Util;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import extend.util.external.TransUtil;
import yagura.model.FilterProperty;
import yagura.model.JSearchProperty;
import yagura.model.JTransCoderProperty;
import yagura.model.MatchReplaceGroup;
import yagura.model.IOptionProperty;

/**
 *
 * @author isayan
 */
public final class LegacyConfig {

    private LegacyConfig() {
    }

    public static String getUserHome() {
        return System.getProperties().getProperty("user.home");
    }

    public static String getExtenderDir() {
        return ".yaguraextender";
    }

    public static String getUserDir() {
        return System.getProperties().getProperty("user.dir");
    }

    public static String getLoggingPropertyName() {
        return "logging.properties";
    }

    public static String getProxyLogMessageName() {
        return "proxy-message.log";
    }

    public static String getToolLogName(String toolName) {
        return String.format("burp_tool_%s.log", toolName);
    }

    /**
     * EncodingNameをBurpのCharSetModeに変換します。
     *
     * @param encodeName
     * @return
     */
    public static String toCharsetMode(String encodeName) {
        String charSetMode = encodeName;
        if ("PlatformDefault".compareToIgnoreCase(encodeName) == 0) {
            charSetMode = "use_the_platform_default";
        } else if ("AutoRecognise".compareToIgnoreCase(encodeName) == 0) {
            charSetMode = "recognize_automatically";
        } else if ("RawBytes".compareToIgnoreCase(encodeName) == 0) {
            charSetMode = "display_as_raw_bytes";
        }
        return charSetMode;
    }

    /**
     * BurpのCharSetModeをEncodingNameに変換します。
     *
     * @param charSetMode
     * @return EncodingName
     */
    public static String toEncodingName(String charSetMode) {
        String encode = charSetMode;
        if ("use_the_platform_default".compareToIgnoreCase(encode) == 0) {
            encode = "PlatformDefault";
        } else if ("recognize_automatically".compareToIgnoreCase(encode) == 0) {
            encode = "AutoRecognise";
        } else if ("display_as_raw_bytes".compareToIgnoreCase(encode) == 0) {
            encode = "RawBytes";
        }
        return encode;
    }

    public static boolean isEncodingName(String charsetMode) {
        return !("use_the_platform_default".compareToIgnoreCase(charsetMode) == 0
                || "recognize_automatically".compareToIgnoreCase(charsetMode) == 0
                || "display_as_raw_bytes".compareToIgnoreCase(charsetMode) == 0);
    }

    /**
     * Propertyファイルの読み込み
     *
     * @param fi ファイル名
     * @param option 設定オプション
     * @throws java.io.IOException
     */
    public static void loadFromXml(File fi, IOptionProperty option) throws IOException {
        IniProp prop = new IniProp();
        prop.loadFromXML(fi);
        loadFromXml(prop, option);
    }

    /**
     * Propertyファイルの読み込み
     *
     * @param content コンテンツ内容
     * @param option 設定オプション
     * @throws java.io.IOException
     */
    public static void loadFromXml(String content, IOptionProperty option) throws IOException {
        IniProp prop = new IniProp();
        prop.loadFromXML(content, StandardCharsets.UTF_8);
        loadFromXml(prop, option);
    }

    protected static void loadFromXml(IniProp prop, IOptionProperty option) throws IOException {
        // Encoding
        UniversalViewProperty encProp = new UniversalViewProperty();
        //encProp.setClipbordAutoDecode(prop.readEntryBool("encoding", "clipbordAutoDecode", false));
        encProp.setClipbordAutoDecode(false);
        List<String> encList = prop.readEntryList("encoding", "list", UniversalViewProperty.getDefaultEncodingList());
        List<String> encSupportList = new ArrayList<String>();
        for (String enc : encList) {
            if (Util.lookupCharset(enc) != null) {
                encSupportList.add(enc);
            }
        }
        encProp.setEncodingList(encSupportList);

        EnumSet<UniversalViewProperty.UniversalView> viewset = EnumSet.noneOf(UniversalViewProperty.UniversalView.class);
        String universal = prop.readEntry("encoding", "universal.view", Util.enumSetToString(encProp.getMessageView()));
        viewset.addAll(UniversalViewProperty.UniversalView.enumSetValueOf(universal));
        encProp.setMessageView(viewset);
        option.setEncodingProperty(encProp);

        // Log
        LoggingProperty logProp = new LoggingProperty();
        logProp.setAutoLogging(prop.readEntryBool("log", "autologging", false));
        logProp.setProxyLog(prop.readEntryBool("log", "proxylog", true));
        logProp.setToolLog(prop.readEntryBool("log", "toollog", true));
        File log_basedir = new File(prop.readEntry("log", "basedir", logProp.getBaseDir()));
        if (log_basedir.isDirectory()) {
            logProp.setBaseDir(log_basedir.getAbsolutePath());
        }
        logProp.setLogDirFormat(prop.readEntry("log", "format", logProp.getLogDirFormat()));
        logProp.setLogFileLimitSize(prop.readEntryInt("log", "limitSize", 0));
        logProp.setLogTimestampFormat(prop.readEntry("log", "timestampformat", logProp.getLogTimestampFormat()));
        logProp.setExclude(prop.readEntryBool("log", "excludeFilter", false));
        logProp.setExcludeExtension(prop.readEntry("log", "excludeFilterExtension", logProp.getExcludeExtension()));
        option.setLoggingProperty(logProp);

        // Match and Rreplace Property list
        String selectedName = prop.readEntry("matchreplace", "selectedName", "(Empty)");
        option.getMatchReplaceProperty().setSelectedName(selectedName);
        Map<String, MatchReplaceGroup> replaceMap = new LinkedHashMap<String, MatchReplaceGroup>();
        List replaceList = prop.readEntryList("matchreplace", "nameList");
        for (Object name : replaceList) {
            String sectionName = String.format("matchreplace.%s", name);
            int count = prop.readEntryInt(sectionName, "count", 0);
            boolean inScopeOnly = prop.readEntryBool(sectionName, "inScopeOnly", false);
            List<MatchReplaceItem> list = new ArrayList<MatchReplaceItem>();
            for (int i = 0; i < count; i++) {
                MatchReplaceItem bean = new MatchReplaceItem();
                bean.setSelected(prop.readEntryBool(sectionName, String.format("item[%d].selected", i), false));
                bean.setType(prop.readEntry(sectionName, String.format("item[%d].type", i), ""));
                bean.setMatch(prop.readEntry(sectionName, String.format("item[%d].match", i), ""));
                bean.setRegexp(prop.readEntryBool(sectionName, String.format("item[%d].regexp", i), true));
                bean.setIgnoreCase(prop.readEntryBool(sectionName, String.format("item[%d].ignore", i), false));
                bean.setReplace(prop.readEntry(sectionName, String.format("item[%d].replace", i), ""));
                bean.setMetaChar(prop.readEntryBool(sectionName, String.format("item[%d].metachar", i), false));
                list.add(bean);
            }
            MatchReplaceGroup group = new MatchReplaceGroup();
            group.setReplaceList(list);
            group.setInScopeOnly(inScopeOnly);
            replaceMap.put((String) name, group);
        }
        option.getMatchReplaceProperty().setReplaceMap(replaceMap);

        // AutoResponder
        List<AutoResponderItem> responderList = new ArrayList<AutoResponderItem>();
        option.getAutoResponderProperty().setAutoResponderEnable(prop.readEntryBool("autoresponder", "enable", false));
        option.getAutoResponderProperty().setRedirectPort(prop.readEntryInt("autoresponder", "redirectPort", 7777));
        int autoresponder_count = prop.readEntryInt("autoresponder", "count", 0);
        for (int i = 0; i < autoresponder_count; i++) {
            AutoResponderItem item = new AutoResponderItem();
            item.setSelected(prop.readEntryBool("autoresponder", String.format("item[%d].selected", i), false));
            item.setMatch(prop.readEntry("autoresponder", String.format("item[%d].match", i), ""));
            item.setRegexp(prop.readEntryBool("autoresponder", String.format("item[%d].regexp", i), true));
            item.setIgnoreCase(prop.readEntryBool("autoresponder", String.format("item[%d].ignorecase", i), false));
            item.setReplace(prop.readEntry("autoresponder", String.format("item[%d].replace", i), ""));
            item.setContentType(prop.readEntry("autoresponder", String.format("item[%d].mime", i), ""));
            item.setBodyOnly(prop.readEntryBool("autoresponder", String.format("item[%d].bodyonly", i), true));
            responderList.add(item);
        }
        option.getAutoResponderProperty().setAutoResponderItemList(responderList);

        // SendToItem
        List<SendToItem> sendToList = new ArrayList<SendToItem>();
        int sendto_count = prop.readEntryInt("sendto", "count", 0);
        for (int i = 0; i < sendto_count; i++) {
            SendToItem item = new SendToItem();
            item.setSelected(prop.readEntryBool("sendto", String.format("item[%d].selected", i), false));
            item.setCaption(prop.readEntry("sendto", String.format("item[%d].caption", i), ""));
            item.setTarget(prop.readEntry("sendto", String.format("item[%d].target", i), ""));
            boolean request = prop.readEntryBool("sendto", String.format("item[%d].request", i), false);
            item.setRequestHeader(prop.readEntryBool("sendto", String.format("item[%d].requestHeader", i), request));
            item.setRequestBody(prop.readEntryBool("sendto", String.format("item[%d].requestBody", i), request));
            boolean response = prop.readEntryBool("sendto", String.format("item[%d].response", i), false);
            item.setResponseHeader(prop.readEntryBool("sendto", String.format("item[%d].responseHeader", i), response));
            item.setResponseBody(prop.readEntryBool("sendto", String.format("item[%d].responseBody", i), response));
            item.setReverseOrder(prop.readEntryBool("sendto", String.format("item[%d].reverseOrder", i), false));

            String hotkey = prop.readEntry("sendto", String.format("item[%d].hotkey", i), null);
            if (!"null".equals(hotkey)) {
                item.setHotkey(SendToItem.parseHotkey(hotkey));
            }
            item.setServer(HttpUtil.startsWithHttp(item.getTarget()));
            String sendExtend = prop.readEntry("sendto", String.format("item[%d].extend", i), "null");
            SendToItem.ExtendType sendExtendType = null;
            if (!"null".equals(sendExtend)) {
                //item.setExtend(SendToItem.ExtendType.valueOf(sendExtend));
                sendExtendType = (SendToItem.ExtendType) Util.parseEnumDefault(SendToItem.ExtendType.class, sendExtend, null);
                if (sendExtendType != null) {
                    item.setExtend(sendExtendType);
                }
            }
            if ((!"null".equals(sendExtend) && sendExtendType != null) || "null".equals(sendExtend)) {
                sendToList.add(item);
            }
        }
        option.getSendToProperty().setSendToItemList(sendToList);
        boolean sendto_submenu = prop.readEntryBool("sendto", "submenu", false);
        option.getSendToProperty().setSubMenu(sendto_submenu);

        // matchalert
        List<MatchAlertItem> alertItemList = new ArrayList<MatchAlertItem>();
        option.getMatchAlertProperty().setMatchAlertEnable(prop.readEntryBool("matchalert", "enable", false));

        int alerts_count = prop.readEntryInt("matchalert", "count", 0);
        for (int i = 0; i < alerts_count; i++) {
            MatchAlertItem item = new MatchAlertItem();
            item.setSelected(prop.readEntryBool("matchalert", String.format("item[%d].selected", i), false));
            item.setType(prop.readEntry("matchalert", String.format("item[%d].type", i), "response"));
            item.setMatch(prop.readEntry("matchalert", String.format("item[%d].match", i), ""));
            item.setRegexp(prop.readEntryBool("matchalert", String.format("item[%d].regexp", i), true));
            item.setIgnoreCase(prop.readEntryBool("matchalert", String.format("item[%d].ignorecase", i), false));
            EnumSet<MatchItem.NotifyType> notyfyset = EnumSet.noneOf(MatchItem.NotifyType.class);
            String notyfys = prop.readEntry("matchalert", String.format("item[%d].notify", i), "[]");
            notyfyset.addAll(MatchItem.NotifyType.enumSetValueOf(notyfys));
            item.setNotifyTypes(notyfyset);

            EnumSet<MatchItem.TargetTool> toolset = EnumSet.noneOf(MatchItem.TargetTool.class);
            String targets = prop.readEntry("matchalert", String.format("item[%d].target", i), "[]");
            toolset.addAll(MatchItem.TargetTool.enumSetValueOf(targets));
            item.setTargetTools(toolset);

            if (item.getNotifyTypes().contains(MatchItem.NotifyType.ITEM_HIGHLIGHT)) {
                String highlightColor = prop.readEntry("matchalert", String.format("item[%d].highlightColor", i), "");
                item.setHighlightColor(MatchItem.HighlightColor.valueOf(highlightColor));
            }

            if (item.getNotifyTypes().contains(MatchItem.NotifyType.COMMENT)) {
                String comment = prop.readEntry("matchalert", String.format("item[%d].comment", i), "");
                item.setComment(comment);
            }

            if (item.getNotifyTypes().contains(MatchItem.NotifyType.SCANNER_ISSUE)) {
                String issueName = prop.readEntry("matchalert", String.format("item[%d].issueName", i), "");
                item.setIssueName(issueName);
                String severity = prop.readEntry("matchalert", String.format("item[%d].severity", i), "");
                item.setSeverity(MatchItem.Severity.valueOf(severity));
                String confidence = prop.readEntry("matchalert", String.format("item[%d].confidence", i), "");
                item.setConfidence(MatchItem.Confidence.valueOf(confidence));
            }

            alertItemList.add(item);
        }
        option.getMatchAlertProperty().setMatchAlertItemList(alertItemList);

        // JSearch Filter
        JSearchProperty jsearch = option.getJSearchProperty();
        jsearch.setSmartMatch(prop.readEntryBool("jsearch", "smartMatch", false));
        jsearch.setRegexp(prop.readEntryBool("jsearch", "regexp", false));
        jsearch.setIgnoreCase(prop.readEntryBool("jsearch", "ignorecase", false));
        jsearch.setAutoRecogniseEncoding(prop.readEntryBool("jsearch", "autoRecogniseEncoding", false));

        jsearch.setRequestHeader(prop.readEntryBool("jsearch", "requestHeader", true));
        jsearch.setRequestBody(prop.readEntryBool("jsearch", "requestBody", true));
        jsearch.setResponseHeader(prop.readEntryBool("jsearch", "responseHeader", true));
        jsearch.setResponseBody(prop.readEntryBool("jsearch", "responseBody", true));
        jsearch.setComment(prop.readEntryBool("jsearch", "comment", true));

        FilterProperty filter = new FilterProperty();
        filter.setShowOnlyScopeItems(prop.readEntryBool("jsearch", "showOnlyScopeItems", false));
        filter.setHideItemsWithoutResponses(prop.readEntryBool("jsearch", "hideItemsWithoutResponsess", false));
        filter.setShowOnly(prop.readEntryBool("jsearch", "showOnly", false));
        filter.setShowOnlyExtension(prop.readEntry("jsearch", "showOnlyExtension", "asp,aspx,jsp,php"));
        filter.setHide(prop.readEntryBool("jsearch", "hide", false));
        filter.setHideExtension(prop.readEntry("jsearch", "hideExtension", "js,gif,jpg,png,css"));
        filter.setStat2xx(prop.readEntryBool("jsearch", "stat2xx", true));
        filter.setStat3xx(prop.readEntryBool("jsearch", "stat3xx", true));
        filter.setStat4xx(prop.readEntryBool("jsearch", "stat4xx", true));
        filter.setStat5xx(prop.readEntryBool("jsearch", "stat5xx", true));
        EnumSet<MatchItem.HighlightColor> highlightColorSet = EnumSet.noneOf(MatchItem.HighlightColor.class);
        String highlightColors = prop.readEntry("jsearch", "highlightColors", Util.enumSetToString(EnumSet.allOf(MatchItem.HighlightColor.class)));
        highlightColorSet.addAll(MatchItem.HighlightColor.enumSetValueOf(highlightColors));
        filter.setHighlightColors(highlightColorSet);
        filter.setComments(prop.readEntryBool("jsearch", "comments", false));
        jsearch.setFilterProperty(filter);

        // JTranscoder
        JTransCoderProperty transcoder = option.getJTransCoderProperty();
        String encodeType = prop.readEntry("transcoder", "encodeType", TransUtil.EncodeType.ALL.name());
        transcoder.setEncodeType(TransUtil.EncodeType.valueOf(encodeType));

        String convertCase = prop.readEntry("transcoder", "convertCase", TransUtil.ConvertCase.LOWLER.name());
        transcoder.setConvertCase(TransUtil.ConvertCase.valueOf(convertCase));

        String newLine = prop.readEntry("transcoder", "newLine", TransUtil.NewLine.NONE.name());
        transcoder.setNewLine(TransUtil.NewLine.valueOf(newLine));

        transcoder.setLineWrap(prop.readEntryBool("transcoder", "lineWrap", false));

        transcoder.setSelectEncoding(prop.readEntry("transcoder", "selectEncoding", "UTF-8"));

        transcoder.setRawEncoding(prop.readEntryBool("transcoder", "rawEncoding", false));
        transcoder.setGuessEncoding(prop.readEntryBool("transcoder", "guessEncoding", false));

    }

    /**
     * Propertyファイルの書き込み
     *
     * @param fo ファイル名
     * @param option 設定オプション
     * @throws java.io.IOException
     */
    public static void saveToXML(File fo, IOptionProperty option) throws IOException {
        IniProp prop = new IniProp();
        saveToXML(prop, option);
        prop.storeToXML(fo, "Temporary Properties", StandardCharsets.UTF_8.name());
    }

    public static String saveToXML(IOptionProperty option) throws IOException {
        IniProp prop = new IniProp();
        saveToXML(prop, option);
        return prop.storeToXML("Temporary Properties", StandardCharsets.UTF_8.name());
    }

    protected static void saveToXML(IniProp prop, IOptionProperty option) throws IOException {

        // Encoding
        prop.writeEntryBool("encoding", "clipbordAutoDecode", option.getEncodingProperty().getClipbordAutoDecode());
        prop.writeEntryList("encoding", "list", option.getEncodingProperty().getEncodingList());

        EnumSet<UniversalViewProperty.UniversalView> universal = option.getEncodingProperty().getMessageView();
        prop.writeEntry("encoding", "universal.view", Util.enumSetToString(universal));

        // Log
        prop.writeEntryBool("log", "autologging", option.getLoggingProperty().isAutoLogging());
        prop.writeEntryBool("log", "proxylog", option.getLoggingProperty().isProxyLog());
        prop.writeEntryBool("log", "toollog", option.getLoggingProperty().isToolLog());

        prop.writeEntry("log", "basedir", option.getLoggingProperty().getBaseDir());
        prop.writeEntry("log", "format", option.getLoggingProperty().getLogDirFormat());
        prop.writeEntryInt("log", "limitSize", option.getLoggingProperty().getLogFileLimitSize());
        prop.writeEntry("log", "timestampformat", option.getLoggingProperty().getLogTimestampFormat());
        prop.writeEntryBool("log", "excludeFilter", option.getLoggingProperty().isExclude());
        prop.writeEntry("log", "excludeFilterExtension", option.getLoggingProperty().getExcludeExtension());

        // SendToItem
        List<SendToItem> sendToList = option.getSendToProperty().getSendToItemList();
        prop.writeEntryInt("sendto", "count", sendToList.size());
        for (int i = 0; i < sendToList.size(); i++) {
            SendToItem item = sendToList.get(i);
            prop.writeEntryBool("sendto", String.format("item[%d].selected", i), item.isSelected());
            prop.writeEntry("sendto", String.format("item[%d].caption", i), item.getCaption());
            prop.writeEntry("sendto", String.format("item[%d].target", i), item.getTarget());
//            prop.writeEntryBool("sendto", String.format("item[%d].request", i), item.isRequest());
            prop.writeEntryBool("sendto", String.format("item[%d].requestHeader", i), item.isRequestHeader());
            prop.writeEntryBool("sendto", String.format("item[%d].requestBody", i), item.isRequestBody());
//            prop.writeEntryBool("sendto", String.format("item[%d].response", i), item.isResponse());
            prop.writeEntryBool("sendto", String.format("item[%d].responseHeader", i), item.isRequestHeader());
            prop.writeEntryBool("sendto", String.format("item[%d].responseBody", i), item.isResponseBody());
            prop.writeEntryBool("sendto", String.format("item[%d].reverseOrder", i), item.isReverseOrder());

            if (item.getHotkey() != null) {
                prop.writeEntry("sendto", String.format("item[%d].hotkey", i), String.valueOf(item.getHotkey()));
            }

            if (item.getExtend() != null) {
                prop.writeEntry("sendto", String.format("item[%d].extend", i), item.getExtend().name());
            }
        }
        prop.writeEntryBool("sendto", "submenu", option.getSendToProperty().isSubMenu());

        // AutoResponder
        prop.writeEntryBool("autoresponder", "enable", option.getAutoResponderProperty().getAutoResponderEnable());
        prop.writeEntryInt("autoresponder", "redirectPort", option.getAutoResponderProperty().getRedirectPort());
        List<AutoResponderItem> responderList = option.getAutoResponderProperty().getAutoResponderItemList();
        prop.writeEntryInt("autoresponder", "count", responderList.size());
        for (int i = 0; i < responderList.size(); i++) {
            AutoResponderItem item = responderList.get(i);
            prop.writeEntryBool("autoresponder", String.format("item[%d].selected", i), item.isSelected());
            prop.writeEntry("autoresponder", String.format("item[%d].match", i), item.getMatch());
            prop.writeEntryBool("autoresponder", String.format("item[%d].regexp", i), item.isRegexp());
            prop.writeEntryBool("autoresponder", String.format("item[%d].ignorecase", i), item.isIgnoreCase());
            prop.writeEntry("autoresponder", String.format("item[%d].replace", i), item.getReplace());
            prop.writeEntry("autoresponder", String.format("item[%d].mime", i), item.getContentType());
            prop.writeEntryBool("autoresponder", String.format("item[%d].bodyonly", i), item.getBodyOnly());
        }

        // Match and Replace
        prop.writeEntry("matchreplace", "selectedName", option.getMatchReplaceProperty().getSelectedName());
        List<String> replaceNameList = option.getMatchReplaceProperty().getReplaceNameList();
        prop.writeEntryList("matchreplace", "nameList", option.getMatchReplaceProperty().getReplaceNameList());
        Map<String, MatchReplaceGroup> replaceMap = option.getMatchReplaceProperty().getReplaceMap();
        for (String name : replaceNameList) {
            // Match and Rreplace Property list
            MatchReplaceGroup group = replaceMap.get(name);
            if (group == null) {
                continue;
            }
            String sectionName = String.format("matchreplace.%s", name);
            prop.writeEntryInt(sectionName, "count", group.getReplaceList().size());
            prop.writeEntryBool(sectionName, "inScopeOnly", group.isInScopeOnly());
            for (int i = 0; i < group.getReplaceList().size(); i++) {
                List<MatchReplaceItem> list = group.getReplaceList();
                MatchReplaceItem bean = list.get(i);
                prop.writeEntry(sectionName, String.format("item[%d].selected", i), String.valueOf(bean.isSelected()));
                prop.writeEntry(sectionName, String.format("item[%d].type", i), bean.getType());
                prop.writeEntry(sectionName, String.format("item[%d].match", i), bean.getMatch());
                prop.writeEntry(sectionName, String.format("item[%d].regexp", i), String.valueOf(bean.isRegexp()));
                prop.writeEntry(sectionName, String.format("item[%d].ignore", i), String.valueOf(bean.isIgnoreCase()));
                prop.writeEntry(sectionName, String.format("item[%d].replace", i), bean.getReplace());
                prop.writeEntry(sectionName, String.format("item[%d].metachar", i), String.valueOf(bean.isMetaChar()));
            }
        }

        // matchalert
        List<MatchAlertItem> alertList = option.getMatchAlertProperty().getMatchAlertItemList();
        prop.writeEntryBool("matchalert", "enable", option.getMatchAlertProperty().isMatchAlertEnable());

        prop.writeEntryInt("matchalert", "count", alertList.size());
        for (int i = 0; i < alertList.size(); i++) {
            MatchAlertItem item = alertList.get(i);
            prop.writeEntryBool("matchalert", String.format("item[%d].selected", i), item.isSelected());
            prop.writeEntry("matchalert", String.format("item[%d].type", i), item.getType());
            prop.writeEntry("matchalert", String.format("item[%d].match", i), item.getMatch());
            prop.writeEntry("matchalert", String.format("item[%d].regexp", i), String.valueOf(item.isRegexp()));
            prop.writeEntryBool("matchalert", String.format("item[%d].ignorecase", i), item.isIgnoreCase());

            //prop.writeEntry("matchalert", String.format("item[%d].notify", i), item.getNotifyType().name());
            EnumSet<MatchItem.NotifyType> notifys = item.getNotifyTypes();
            prop.writeEntry("matchalert", String.format("item[%d].notify", i), Util.enumSetToString(notifys));
            if (item.getNotifyTypes().contains(MatchItem.NotifyType.ITEM_HIGHLIGHT)) {
                prop.writeEntry("matchalert", String.format("item[%d].highlightColor", i), item.getHighlightColor().name());
            }

            if (item.getNotifyTypes().contains(MatchItem.NotifyType.COMMENT)) {
                prop.writeEntry("matchalert", String.format("item[%d].comment", i), item.getComment());
            }

            if (item.getNotifyTypes().contains(MatchItem.NotifyType.SCANNER_ISSUE)) {
                prop.writeEntry("matchalert", String.format("item[%d].issueName", i), item.getIssueName());
                prop.writeEntry("matchalert", String.format("item[%d].severity", i), item.getSeverity().name());
                prop.writeEntry("matchalert", String.format("item[%d].confidence", i), item.getConfidence().name());
            }

            EnumSet<MatchItem.TargetTool> tools = item.getTargetTools();
            prop.writeEntry("matchalert", String.format("item[%d].target", i), Util.enumSetToString(tools));

        }

        // JSearch Filter
        JSearchProperty jsearch = option.getJSearchProperty();
        prop.writeEntryBool("jsearch", "smartMatch", jsearch.isSmartMatch());
        prop.writeEntryBool("jsearch", "regexp", jsearch.isRegexp());
        prop.writeEntryBool("jsearch", "ignorecase", jsearch.isIgnoreCase());
        prop.writeEntryBool("jsearch", "autoRecogniseEncoding", jsearch.isAutoRecogniseEncoding());

        prop.writeEntryBool("jsearch", "requestHeader", jsearch.isRequestHeader());
        prop.writeEntryBool("jsearch", "requestBody", jsearch.isRequestBody());
        prop.writeEntryBool("jsearch", "responseHeader", jsearch.isResponseHeader());
        prop.writeEntryBool("jsearch", "responseBody", jsearch.isResponseBody());
        prop.writeEntryBool("jsearch", "comment", jsearch.isComment());

        FilterProperty filter = jsearch.getFilterProperty();
        prop.writeEntryBool("jsearch", "showOnlyScopeItems", filter.getShowOnlyScopeItems());
        prop.writeEntryBool("jsearch", "hideItemsWithoutResponsess", filter.isHideItemsWithoutResponses());
        prop.writeEntryBool("jsearch", "showOnly", filter.getShowOnly());
        prop.writeEntry("jsearch", "showOnlyExtension", filter.getShowOnlyExtension());
        prop.writeEntryBool("jsearch", "hide", filter.getHide());
        prop.writeEntry("jsearch", "hideExtension", filter.getHideExtension());
        prop.writeEntryBool("jsearch", "stat2xx", filter.getStat2xx());
        prop.writeEntryBool("jsearch", "stat3xx", filter.getStat3xx());
        prop.writeEntryBool("jsearch", "stat4xx", filter.getStat4xx());
        prop.writeEntryBool("jsearch", "stat5xx", filter.getStat5xx());
        prop.writeEntry("jsearch", "highlightColors", Util.enumSetToString(filter.getHighlightColors()));
        prop.writeEntryBool("jsearch", "comments", filter.getComments());

        // JTranscoder
        JTransCoderProperty transcoder = option.getJTransCoderProperty();
        prop.writeEntry("transcoder", "encodeType", transcoder.getEncodeType().name());
        prop.writeEntry("transcoder", "convertCase", transcoder.getConvertCase().name());
        prop.writeEntry("transcoder", "newLine", transcoder.getNewLine().name());
        prop.writeEntryBool("transcoder", "lineWrap", transcoder.isLineWrap());

        prop.writeEntry("transcoder", "selectEncoding", transcoder.getSelectEncoding());

        prop.writeEntryBool("transcoder", "rawEncoding", transcoder.isRawEncoding());
        prop.writeEntryBool("transcoder", "guessEncoding", transcoder.isGuessEncoding());

    }

}
