package yagura.model;

import burp.api.montoya.http.message.HttpRequestResponse;
import extend.util.external.TransUtil;
import extension.helpers.ConvertUtil;
import extension.helpers.HttpResponseWapper;
import extension.helpers.HttpUtil;
import extension.helpers.SmartCodec;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author isayan
 */
public class SendToParameterProperty {
    private final static Logger logger = Logger.getLogger(SendToParameterProperty.class.getName());

    public enum SendToParameterType {
        HISTORY_COMMENT, RESPONSE_TITLE, HISTORY_NUMBER
    };

    public enum LinePartType {
        ALL_LINE, FIRST_LINE, SECOND_LINE
    };

    private boolean useOverride = false;

    private boolean useReqName = false;

    private boolean useReqComment = false;

    private boolean useReqNum = false;

    private SendToParameterType reqName = SendToParameterType.HISTORY_COMMENT;

    private LinePartType reqNameLineType = LinePartType.FIRST_LINE;

    private SendToParameterType reqComment = SendToParameterType.HISTORY_COMMENT;

    private LinePartType reqCommentLineType = LinePartType.SECOND_LINE;

    private SendToParameterType reqNum = SendToParameterType.HISTORY_NUMBER;

    private boolean useDummyResponse = false;

    /**
     * @return the useOverride
     */
    public boolean isUseOverride() {
        return useOverride;
    }

    /**
     * @param useOverride the useOverride to set
     */
    public void setUseOverride(boolean useOverride) {
        this.useOverride = useOverride;
    }

    /**
     * @return the useReqName
     */
    public boolean isUseReqName() {
        return useReqName;
    }

    /**
     * @param useReqName the useReqName to set
     */
    public void setUseReqName(boolean useReqName) {
        this.useReqName = useReqName;
    }

    /**
     * @return the useReqComment
     */
    public boolean isUseReqComment() {
        return useReqComment;
    }

    /**
     * @param useReqComment the useReqComment to set
     */
    public void setUseReqComment(boolean useReqComment) {
        this.useReqComment = useReqComment;
    }

    /**
     * @return the useReqNum
     */
    public boolean isUseReqNum() {
        return useReqNum;
    }

    /**
     * @param useReqNum the useReqNum to set
     */
    public void setUseReqNum(boolean useReqNum) {
        this.useReqNum = useReqNum;
    }

    /**
     * @return the reqName
     */
    public SendToParameterType getReqName() {
        return reqName;
    }

    /**
     * @param reqName the reqName to set
     */
    public void setReqName(SendToParameterType reqName) {
        this.reqName = reqName;
    }

    /**
     * @return the reqComment
     */
    public SendToParameterType getReqComment() {
        return reqComment;
    }

    /**
     * @param reqComment the reqComment to set
     */
    public void setReqComment(SendToParameterType reqComment) {
        this.reqComment = reqComment;
    }

    /**
     * @return the reqNum
     */
    public SendToParameterType getReqNum() {
        return reqNum;
    }

    /**
     * @param reqNum the reqNum to set
     */
    public void setReqNum(SendToParameterType reqNum) {
        this.reqNum = reqNum;
    }

    /**
     * @return the reqNameLineType
     */
    public LinePartType getReqNameLineType() {
        return reqNameLineType;
    }

    /**
     * @param reqNameHistoryCommentType the reqNameLineType to set
     */
    public void setReqNameLineType(LinePartType reqNameHistoryCommentType) {
        this.reqNameLineType = reqNameHistoryCommentType;
    }

    /**
     * @return the reqCommentLineType
     */
    public LinePartType getReqCommentLineType() {
        return reqCommentLineType;
    }

    /**
     * @param reqCommentHistoryCommentType the reqCommentLineType to set
     */
    public void setReqCommentLineType(LinePartType reqCommentHistoryCommentType) {
        this.reqCommentLineType = reqCommentHistoryCommentType;
    }

    /**
     * @return the useDummyResponse
     */
    public boolean isUseDummyResponse() {
        return useDummyResponse;
    }

    /**
     * @param useDummyResponse the useDummyResponse to set
     */
    public void setUseDummyResponse(boolean useDummyResponse) {
        this.useDummyResponse = useDummyResponse;
    }

    public void setProperty(SendToParameterProperty property) {
        this.useOverride = property.useOverride;

        this.useReqName = property.useReqName;
        this.useReqComment = property.useReqComment;
        this.reqNameLineType = property.reqNameLineType;
        this.useReqNum = property.useReqNum;

        this.reqName = property.reqName;
        this.reqComment = property.reqComment;
        this.reqCommentLineType = property.reqCommentLineType;
        this.reqNum = property.reqNum;

        this.useDummyResponse = property.useDummyResponse;
    }

    public void setProperties(Properties prop) {
        this.useOverride = ConvertUtil.parseBooleanDefault(prop.getProperty("SendToPamareter.useOverride"), false);;
        this.useReqName = ConvertUtil.parseBooleanDefault(prop.getProperty("SendToPamareter.useReqName"), false);
        this.useReqComment = ConvertUtil.parseBooleanDefault(prop.getProperty("SendToPamareter.useReqComment"), false);
        this.reqNameLineType = LinePartType.valueOf(prop.getProperty("SendToPamareter.reqNameLineType", LinePartType.FIRST_LINE.name()));

        this.useReqNum = ConvertUtil.parseBooleanDefault(prop.getProperty("SendToPamareter.useReqNum"), false);

        this.reqName = SendToParameterType.valueOf(prop.getProperty("SendToPamareter.reqName", SendToParameterType.HISTORY_COMMENT.name()));
        this.reqComment = SendToParameterType.valueOf(prop.getProperty("SendToPamareter.reqComment", SendToParameterType.HISTORY_COMMENT.name()));
        this.reqCommentLineType = LinePartType.valueOf(prop.getProperty("SendToPamareter.reqCommentLineType", LinePartType.SECOND_LINE.name()));
        this.reqNum = SendToParameterType.valueOf(prop.getProperty("SendToPamareter.reqNum", SendToParameterType.HISTORY_NUMBER.name()));

        this.useDummyResponse = ConvertUtil.parseBooleanDefault(prop.getProperty("SendToPamareter.useDummyResponse"), false);

    }

    public Properties getProperties() {
        Properties prop = new Properties();
        prop.setProperty("SendToPamareter.useOverride", Boolean.toString(this.useOverride));

        prop.setProperty("SendToPamareter.useReqName", Boolean.toString(this.useReqName));
        prop.setProperty("SendToPamareter.useReqComment", Boolean.toString(this.useReqComment));
        prop.setProperty("SendToPamareter.useReqNum", Boolean.toString(this.useReqNum));

        prop.setProperty("SendToPamareter.reqName", this.reqName.name());
        prop.setProperty("SendToPamareter.reqNameLineType", this.reqNameLineType.name());
        prop.setProperty("SendToPamareter.reqComment", this.reqComment.name());
        prop.setProperty("SendToPamareter.reqCommentLineType", this.reqCommentLineType.name());
        prop.setProperty("SendToPamareter.reqNum", this.reqNum.name());
        prop.setProperty("SendToPamareter.useDummyResponse", Boolean.toString(this.useDummyResponse));
        return prop;
    }

    public static String getParameter(SendToParameterProperty.SendToParameterType type, HttpRequestResponse messageInfo) {
        String value = null;
        switch (type) {
            case HISTORY_COMMENT:
                value = messageInfo.annotations().notes();
                break;
            case RESPONSE_TITLE:
                if (messageInfo.response() != null) {
                    try {
                        HttpResponseWapper wrapResponse = new HttpResponseWapper(messageInfo.response());
                        String body = wrapResponse.getBodyString(wrapResponse.getGuessCharset(StandardCharsets.UTF_8.name()), false);
                        value = HttpUtil.extractHTMLTitle(body);
                        if (value != null) {
                            TransUtil.EncodePattern patern = TransUtil.getSmartDecode(value);
                            if (patern == TransUtil.EncodePattern.HTML) {
                                value = SmartCodec.toHtmlUnicodeDecode(value);
                            }
                        }
                    } catch (UnsupportedEncodingException ex) {
                        logger.log(Level.SEVERE, ex.getMessage(), ex);
                    }
                }
                break;
            case HISTORY_NUMBER:
                break;
        }
        return value;
    }

    private final static Pattern LINE_PART = Pattern.compile("(.*?)(?:\\r\\n|\\r|\\n)(?:\\r\\n|\\r|\\n)?(.*)", Pattern.DOTALL);

    public static String extractLinePart(SendToParameterProperty.LinePartType commentLineType, String value) {
        String part = value;
        Matcher m = LINE_PART.matcher(part);
        if (m.find()) {
            switch (commentLineType) {
                case FIRST_LINE:
                    part = m.group(1);
                    break;
                case SECOND_LINE:
                    part = m.group(2);
                    break;
                default:
                    break;
            }
        }
        return part;
    }

}
