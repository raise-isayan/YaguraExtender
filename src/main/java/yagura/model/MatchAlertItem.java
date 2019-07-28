package yagura.model;

import extend.view.base.MatchItem;
import java.util.EnumSet;

/**
 *
 * @author isayan
 */
public class MatchAlertItem extends MatchItem {

    private EnumSet<TargetTool> targetTools = EnumSet.allOf(TargetTool.class);
    private EnumSet<NotifyType> notifyTypes = EnumSet.noneOf(NotifyType.class);
    private static final String[] MESSAGE_TYPE = new String[]{"request", "response"};

    public MatchAlertItem() {
        super();
        this.setType(MESSAGE_TYPE[1]);
    }

    public static String[] getTypes() {
        return MESSAGE_TYPE;
    }

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
    private MatchItem.HighlightColor highlightColor = null;

    /**
     * @return the highlightColor
     */
    public HighlightColor getHighlightColor() {
        return this.highlightColor;
    }

    /**
     * @param highlightColor the highlightColor to set
     */
    public void setHighlightColor(MatchItem.HighlightColor highlightColor) {
        this.highlightColor = highlightColor;
    }

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
    public void setSeverity(MatchItem.Severity serverity) {
        this.serverity = serverity;
    }

    private MatchItem.Confidence confidence = MatchItem.Confidence.CERTAIN;

    /**
     * @return the confidence
     */
    public MatchItem.Confidence getConfidence() {
        return confidence;
    }

    /**
     * @param confidence the confidence to set
     */
    public void setConfidence(MatchItem.Confidence confidence) {
        this.confidence = confidence;
    }

    public boolean isRequest() {
        return this.getType().startsWith("request");
    }

    public boolean isResponse() {
        return this.getType().startsWith("response");
    }

    public static Object[] toObjects(MatchAlertItem matchAlert) {
        Object[] beans = new Object[12];
        beans[0] = matchAlert.isSelected();
        beans[1] = matchAlert.getType();
        beans[2] = matchAlert.getMatch();
        beans[3] = matchAlert.isRegexp();
        beans[4] = matchAlert.isIgnoreCase();
        beans[5] = matchAlert.getNotifyTypes();
        beans[6] = matchAlert.getTargetTools();
        beans[7] = matchAlert.getHighlightColor();
        beans[8] = matchAlert.getComment();
        beans[9] = matchAlert.getIssueName();
        beans[10] = matchAlert.getSeverity();
        beans[11] = matchAlert.getConfidence();
        return beans;
    }

    @SuppressWarnings("unchecked")
    public static MatchAlertItem fromObjects(Object[] rows) {
        MatchAlertItem matchAlert = new MatchAlertItem();
        matchAlert.setSelected(((Boolean) rows[0]));
        matchAlert.setType((String) rows[1]);
        matchAlert.setMatch((String) rows[2]);
        matchAlert.setRegexp((Boolean) rows[3]);
        matchAlert.setIgnoreCase((Boolean) rows[4]);
        matchAlert.setNotifyTypes((EnumSet<NotifyType>) rows[5]);
        matchAlert.setTargetTools((EnumSet<TargetTool>) rows[6]);
        matchAlert.setHighlightColor((HighlightColor) rows[7]);
        matchAlert.setComment((String) rows[8]);
        matchAlert.setIssueName((String) rows[9]);
        matchAlert.setSeverity((Severity) rows[10]);
        matchAlert.setConfidence((Confidence) rows[11]);
        return matchAlert;
    }

}
