package yagura.model;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.JsonAdapter;
import extend.util.external.gson.XMatchItemAdapter;
import extension.burp.Confidence;
import extension.burp.MessageHighlightColor;
import extension.burp.NotifyType;
import extension.burp.Severity;
import extension.burp.TargetTool;
import extension.helpers.MatchUtil;
import extension.view.base.MatchItem;
import java.util.EnumSet;
import java.util.regex.Pattern;

/**
 *
 * @author isayan
 */
@JsonAdapter(XMatchItemAdapter.class)
public class MatchAlertItem extends MatchItem {

    private static final String[] MESSAGE_TYPE = new String[]{"request", "response"};

    public MatchAlertItem() {
        super();
        this.setType(MESSAGE_TYPE[1]);
    }

    @Override
    public Pattern compileRegex(boolean quote) {
        return MatchUtil.compileRegex(this.getMatch(), this.isSmartMatch(), !quote, this.isIgnoreCase(), Pattern.MULTILINE);
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
    private MessageHighlightColor highlightColor = null;

    /**
     * @return the highlightColor
     */
    public MessageHighlightColor getHighlightColor() {
        return this.highlightColor;
    }

    /**
     * @param highlightColor the highlightColor to set
     */
    public void setHighlightColor(MessageHighlightColor highlightColor) {
        this.highlightColor = highlightColor;
    }

    @Expose
    private String notes = "";

    /**
     * @return the notes
     */
    public String getNotes() {
        return this.notes;
    }

    /**
     * @param notes the notes to set
     */
    public void setNotes(String notes) {
        this.notes = notes;
    }

    @Expose
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

    @Expose
    private boolean captureGroup = false;

    /**
     * @return the captureGroup
     */
    public boolean isCaptureGroup() {
        return captureGroup;
    }

    /**
     * @param captureGroup the captureGroup to set
     */
    public void setCaptureGroup(boolean captureGroup) {
        this.captureGroup = captureGroup;
    }

    public static Object[] toObjects(MatchAlertItem matchAlert) {
        Object[] beans = new Object[14];
        beans[0] = matchAlert.isSelected();
        beans[1] = matchAlert.getType();
        beans[2] = matchAlert.getMatch();
        beans[3] = matchAlert.isSmartMatch();
        beans[4] = matchAlert.isRegexp();
        beans[5] = matchAlert.isIgnoreCase();
        beans[6] = matchAlert.isCaptureGroup();
        beans[7] = matchAlert.getNotifyTypes();
        beans[8] = matchAlert.getTargetTools();
        beans[9] = matchAlert.getHighlightColor();
        beans[10] = matchAlert.getNotes();
        beans[11] = matchAlert.getIssueName();
        beans[12] = matchAlert.getSeverity();
        beans[13] = matchAlert.getConfidence();
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
        matchAlert.setCaptureGroup((Boolean) rows[6]);
        matchAlert.setNotifyTypes((EnumSet<NotifyType>) rows[7]);
        matchAlert.setTargetTools((EnumSet<TargetTool>) rows[8]);
        matchAlert.setHighlightColor((MessageHighlightColor) rows[9]);
        matchAlert.setNotes((String) rows[10]);
        matchAlert.setIssueName((String) rows[11]);
        matchAlert.setSeverity((Severity) rows[12]);
        matchAlert.setConfidence((Confidence) rows[13]);
        matchAlert.recompileRegex(!matchAlert.isRegexp());
        return matchAlert;
    }

    public void setProperty(MatchAlertItem item) {
        this.setProperty((MatchItem) item);
        this.setSmartMatch(item.isSmartMatch());
        this.setCaptureGroup(item.isCaptureGroup());
        this.setIssueName(item.getIssueName());
        this.setSeverity(item.getSeverity());
        this.setConfidence(item.getConfidence());
        this.setTargetTools(item.getTargetTools());
        this.setHighlightColor(item.getHighlightColor());
        this.setNotifyTypes(item.getNotifyTypes());
        this.setNotes(item.getNotes());
    }

}
