package yagura.model;

import com.google.gson.annotations.Expose;
import extend.util.external.TransUtil;
import extension.burp.Confidence;
import extension.burp.HighlightColor;
import extension.burp.NotifyType;
import extension.burp.Severity;
import extension.burp.TargetTool;
import extension.view.base.MatchItem;
import java.util.EnumSet;
import java.util.regex.Pattern;

/**
 *
 * @author isayan
 */
public class MatchAlertItem extends MatchItem {
    private static final String[] MESSAGE_TYPE = new String[]{"request", "response"};

    public MatchAlertItem() {
        super();
        this.setType(MESSAGE_TYPE[1]);
    }

    @Override
    public Pattern compileRegex(boolean quote) {
        return TransUtil.compileRegex(this.getMatch(), this.isSmartMatch(), !quote, this.isIgnoreCase(), Pattern.MULTILINE);
    }
    
    public static String[] getTypes() {
        return MESSAGE_TYPE;
    }

    @Expose
    private boolean smartMatch = false;

    public void setSmartMatch(boolean value) {
        this.smartMatch = value;
    }

    public boolean isSmartMatch() {
        return this.smartMatch;
    }
        
    @Expose
    private EnumSet<NotifyType> notifyTypes = EnumSet.noneOf(NotifyType.class);

    /**
     * @return the notifyTypes
     */
    public EnumSet<NotifyType> getNotifyTypes() {
        return this.notifyTypes;
    }

    /**
     * @param notifyTypes the notifyType to set
     */
    public void setNotifyTypes(EnumSet<NotifyType> notifyTypes) {
        this.notifyTypes = notifyTypes;
    }

    @Expose
    private EnumSet<TargetTool> targetTools = EnumSet.allOf(TargetTool.class);
    
    /**
     * @return the targetTools
     */
    public EnumSet<TargetTool> getTargetTools() {
        return this.targetTools;
    }

    /**
     * @param targetTools the targetTools to set
     */
    public void setTargetTools(EnumSet<TargetTool> targetTools) {
        this.targetTools = targetTools;
    }

    @Expose
    private HighlightColor highlightColor = null;

    /**
     * @return the highlightColor
     */
    public HighlightColor getHighlightColor() {
        return this.highlightColor;
    }

    /**
     * @param highlightColor the highlightColor to set
     */
    public void setHighlightColor(HighlightColor highlightColor) {
        this.highlightColor = highlightColor;
    }

    @Expose
    private String comment = "";

    /**
     * @return the comment
     */
    public String getComment() {
        return this.comment;
    }

    /**
     * @param comment the comment to set
     */
    public void setComment(String comment) {
        this.comment = comment;
    }

    private String issueName = "";

    /**
     * @return the issueName
     */
    public String getIssueName() {
        return issueName;
    }

    /**
     * @param issueName the issueName to set
     */
    public void setIssueName(String issueName) {
        this.issueName = issueName;
    }

    @Expose
    private Severity serverity = Severity.INFORMATION;

    /**
     * @return the serverity
     */
    public Severity getSeverity() {
        return serverity;
    }

    /**
     * @param serverity the serverity to set
     */
    public void setSeverity(Severity serverity) {
        this.serverity = serverity;
    }

    @Expose
    private Confidence confidence = Confidence.CERTAIN;

    /**
     * @return the confidence
     */
    public Confidence getConfidence() {
        return confidence;
    }

    /**
     * @param confidence the confidence to set
     */
    public void setConfidence(Confidence confidence) {
        this.confidence = confidence;
    }

    public boolean isRequest() {
        return this.getType().startsWith("request");
    }

    public boolean isResponse() {
        return this.getType().startsWith("response");
    }

    public static Object[] toObjects(MatchAlertItem matchAlert) {
        Object[] beans = new Object[13];
        beans[0] = matchAlert.isSelected();
        beans[1] = matchAlert.getType();
        beans[2] = matchAlert.getMatch();
        beans[3] = matchAlert.isSmartMatch();
        beans[4] = matchAlert.isRegexp();
        beans[5] = matchAlert.isIgnoreCase();
        beans[6] = matchAlert.getNotifyTypes();
        beans[7] = matchAlert.getTargetTools();
        beans[8] = matchAlert.getHighlightColor();
        beans[9] = matchAlert.getComment();
        beans[10] = matchAlert.getIssueName();
        beans[11] = matchAlert.getSeverity();
        beans[12] = matchAlert.getConfidence();
        return beans;
    }

    @SuppressWarnings("unchecked")
    public static MatchAlertItem fromObjects(Object[] rows) {
        MatchAlertItem matchAlert = new MatchAlertItem();
        matchAlert.setSelected(((Boolean) rows[0]));
        matchAlert.setType((String) rows[1]);
        matchAlert.setMatch((String) rows[2]);
        matchAlert.setSmartMatch((Boolean) rows[3]);
        matchAlert.setRegexp((Boolean) rows[4]);
        matchAlert.setIgnoreCase((Boolean) rows[5]);
        matchAlert.setNotifyTypes((EnumSet<NotifyType>) rows[6]);
        matchAlert.setTargetTools((EnumSet<TargetTool>) rows[7]);
        matchAlert.setHighlightColor((HighlightColor) rows[8]);
        matchAlert.setComment((String) rows[9]);
        matchAlert.setIssueName((String) rows[10]);
        matchAlert.setSeverity((Severity) rows[11]);
        matchAlert.setConfidence((Confidence) rows[12]);
        return matchAlert;
    }

    public void setProperty(MatchItem item) {
        this.setSelected(item.isSelected());
        this.setType(item.getType());
        this.setMatch(item.getMatch());
        this.setIgnoreCase(item.isIgnoreCase());
        this.setRegexp(item.isRegexp());
        this.setReplace(item.getReplace());
    }
    
    public void setProperty(MatchAlertItem item) {
        this.setProperty((MatchItem)item);
        this.setSmartMatch(item.isSmartMatch());
        this.setIssueName(item.getIssueName());
        this.setSeverity(item.getSeverity());
        this.setConfidence(item.getConfidence());
        this.setTargetTools(item.getTargetTools());
        this.setHighlightColor(item.getHighlightColor());
        this.setNotifyTypes(item.getNotifyTypes());
        this.setComment(item.getComment());
    }
        
}
