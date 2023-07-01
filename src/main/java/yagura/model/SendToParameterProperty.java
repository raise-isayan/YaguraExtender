package yagura.model;

import extension.helpers.ConvertUtil;
import java.util.Properties;

/**
 *
 * @author isayan
 */
public class SendToParameterProperty {

    public enum SendToParameterType {
        HISTORY_COMMENT, RESPONSE_TITLE, HISTORY_NUMBER
    };

    private boolean useOverride = false;

    private boolean useReqName = false;

    private boolean useReqComment = false;

    private boolean useReqNum = false;

    private SendToParameterType reqName = SendToParameterType.RESPONSE_TITLE;

    private SendToParameterType reqComment = SendToParameterType.HISTORY_COMMENT;

    private SendToParameterType reqNum = SendToParameterType.HISTORY_NUMBER;

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

    public void setProperty(SendToParameterProperty property) {
        this.useOverride = property.useOverride;

        this.useReqName = property.useReqName;
        this.useReqComment = property.useReqComment;
        this.useReqNum = property.useReqNum;

        this.reqName = property.reqName;
        this.reqComment = property.reqComment;
        this.reqNum = property.reqNum;
    }

    public void setProperties(Properties prop) {
        this.useOverride = ConvertUtil.parseBooleanDefault(prop.getProperty("SendToPamareter.useOverride"), false);;

        this.useReqName = ConvertUtil.parseBooleanDefault(prop.getProperty("SendToPamareter.useReqName"), false);
        this.useReqComment = ConvertUtil.parseBooleanDefault(prop.getProperty("SendToPamareter.useReqComment"), false);
        this.useReqNum = ConvertUtil.parseBooleanDefault(prop.getProperty("SendToPamareter.useReqNum"), false);

        this.reqName = SendToParameterType.valueOf(prop.getProperty("SendToPamareter.reqName", SendToParameterType.RESPONSE_TITLE.name()));
        this.reqComment = SendToParameterType.valueOf(prop.getProperty("SendToPamareter.reqComment", SendToParameterType.HISTORY_COMMENT.name()));
        this.reqNum = SendToParameterType.valueOf(prop.getProperty("SendToPamareter.reqNum", SendToParameterType.HISTORY_NUMBER.name()));
    }

    public Properties getProperties() {
        Properties prop = new Properties();
        prop.setProperty("SendToPamareter.useOverride", Boolean.toString(this.useOverride));

        prop.setProperty("SendToPamareter.useReqName", Boolean.toString(this.useReqName));
        prop.setProperty("SendToPamareter.useReqComment", Boolean.toString(this.useReqComment));
        prop.setProperty("SendToPamareter.useReqNum", Boolean.toString(this.useReqNum));

        prop.setProperty("SendToPamareter.reqName", this.reqName.name());
        prop.setProperty("SendToPamareter.reqComment", this.reqComment.name());
        prop.setProperty("SendToPamareter.reqNum", this.reqNum.name());
        return prop;
    }

}
