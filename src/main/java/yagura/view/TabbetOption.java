package yagura.view;

import extension.helpers.BurpUtil;
import java.awt.Component;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import yagura.Version;
import yagura.model.UniversalViewProperty;
import yagura.model.LoggingProperty;
import yagura.model.MatchAlertProperty;
import yagura.model.MatchReplaceProperty;
import yagura.model.SendToProperty;
import yagura.model.JSearchProperty;
import yagura.model.JTransCoderProperty;
import yagura.model.OptionProperty;
import extension.burp.IBurpTab;

/**
 *
 * @author isayan
 */
public class TabbetOption extends javax.swing.JTabbedPane implements IBurpTab, PropertyChangeListener {
    public final static String VERSION_PROPERTY = "versionProperty";
    public final static String LOAD_CONFIG_PROPERTY = "loadConfigProperty";

    public TabbetOption() {
        super();
        customizeComponents();
    }

    public TabbetOption(int tabPlacement) {
        super(tabPlacement, WRAP_TAB_LAYOUT);
        customizeComponents();
    }

    public TabbetOption(int tabPlacement, int tabLayoutPolicy) {
        super(tabPlacement, tabLayoutPolicy);
        customizeComponents();
    }

    private final UniversalViewTab tabUniversalView = new UniversalViewTab();
    private final MatchReplaceTab tabMatchReplace = new MatchReplaceTab();
    private final MatchAlertTab tabMatchAlert = new MatchAlertTab();
//    private final AutoResponderTab tabAutoResponder = new AutoResponderTab();
    private final SendToTab tabSendTo = new SendToTab();
    private final LoggingTab tabLogging = new LoggingTab();
    private final JSearchTab tabJSearch = new JSearchTab();
    private final JTransCoderTab tabJTransCoder = new JTransCoderTab();

    private final VersionTab tabVersion = new VersionTab();

    @SuppressWarnings("unchecked")
    private void customizeComponents() {
        this.addTab(this.tabUniversalView.getTabCaption(), this.tabUniversalView);
        this.addTab(this.tabMatchReplace.getTabCaption(), this.tabMatchReplace);
        this.addTab(this.tabMatchAlert.getTabCaption(), this.tabMatchAlert);
        //      this.addTab(this.tabAutoResponder.getTabCaption(), this.tabAutoResponder);
        this.addTab(this.tabSendTo.getTabCaption(), this.tabSendTo);
        this.addTab(this.tabLogging.getTabCaption(), this.tabLogging);
        this.addTab(this.tabJSearch.getTabCaption(), this.tabJSearch);
        this.addTab(this.tabJTransCoder.getTabCaption(), this.tabJTransCoder);
//        this.addTab("RapidFire", this.tabRapidFireTab);
        this.addTab(this.tabVersion.getTabCaption(), this.tabVersion);

        this.tabUniversalView.addPropertyChangeListener(UniversalViewProperty.CJK_VIEW_PROPERTY, this);
        this.tabMatchReplace.addPropertyChangeListener(MatchReplaceProperty.MATCHREPLACE_PROPERTY, this);
        this.tabMatchAlert.addPropertyChangeListener(MatchAlertProperty.MATCHALERT_PROPERTY, this);
//        this.tabAutoResponder.addPropertyChangeListener(AUTO_RESPONDER_PROPERTY, this);
        this.tabSendTo.addPropertyChangeListener(SendToProperty.SENDTO_PROPERTY, this);
        this.tabLogging.addPropertyChangeListener(LoggingProperty.LOGGING_PROPERTY, this);
        this.tabJSearch.addPropertyChangeListener(JSearchProperty.JSEARCH_FILTER_PROPERTY, this);
        this.tabJTransCoder.addPropertyChangeListener(JTransCoderProperty.JTRANS_CODER_PROPERTY, this);
        this.tabVersion.addPropertyChangeListener(VERSION_PROPERTY, this);
        this.tabVersion.addPropertyChangeListener(LOAD_CONFIG_PROPERTY, this);
    }

    /**
     * Burp uses this method to obtain the caption that should appear on the
     * custom tab when it is displayed.
     *
     * @return The caption that should appear on the custom tab when it is
     * displayed.
     */
    @Override
    public String getTabCaption() {
        return Version.getInstance().getTabCaption();
//        return Config.getTabCaption();
    }

    /**
     * Burp uses this method to obtain the component that should be used as the
     * contents of the custom tab when it is displayed.
     *
     * @return The component that should be used as the contents of the custom
     * tab when it is displayed.
     */
    @Override
    public Component getUiComponent() {
        return this;
    }

    public void setProperty(OptionProperty property) {
        this.setEncodingProperty(property.getEncodingProperty());
        this.setLoggingProperty(property.getLoggingProperty());
        this.setMatchReplaceProperty(property.getMatchReplaceProperty());
//        this.setAutoResponderProperty(property.getAutoResponderProperty());
        this.setMatchAlertProperty(property.getMatchAlertProperty());
        this.setSendToProperty(property.getSendToProperty());
        this.setJSearchProperty(property.getJSearchProperty());
        this.setJTransCoderProperty(property.getJTransCoderProperty());
        // common
        this.setDebugMode(property.getDebugMode());
        this.setJTransCoderProperty(property.getEncodingProperty());
    }

    public boolean isLogDirChanged() {
        return this.tabLogging.isLogDirChanged();
    }

    public boolean isHistoryLogInclude() {
        return this.tabLogging.isHistoryLogInclude();
    }

    public void setEncodingProperty(UniversalViewProperty encProperty) {
        this.tabUniversalView.setEncodingProperty(encProperty);
    }

    public UniversalViewProperty getEncodingProperty() {
        return this.tabUniversalView.getEncodingProperty();
    }

    public void setMatchReplaceProperty(MatchReplaceProperty matchReplaceProperty) {
        this.tabMatchReplace.setMatchReplaceProperty(matchReplaceProperty);
    }

    public MatchReplaceProperty getMatchReplaceProperty() {
        return this.tabMatchReplace.getMatchReplaceProperty();
    }

    public void setSendToProperty(SendToProperty sendToProperty) {
        this.tabSendTo.setSendToProperty(sendToProperty);
    }

    public SendToProperty getSendToProperty() {
        return this.tabSendTo.getSendToProperty();
    }

    public void setLoggingProperty(LoggingProperty loggingProperty) {
        this.tabLogging.setLoggingProperty(loggingProperty);
    }

    public LoggingProperty getLoggingProperty() {
        return tabLogging.getLoggingProperty();
    }

    public MatchAlertProperty getMatchAlertProperty() {
        return this.tabMatchAlert.getMatchAlertProperty();
    }

    public void setMatchAlertProperty(MatchAlertProperty matchAlertProperty) {
        this.tabMatchAlert.setMatchAlertProperty(matchAlertProperty);
    }

    public JSearchProperty getJSearchProperty() {
        return this.tabJSearch.getProperty();
    }


    public void setJSearchProperty(JSearchProperty jsearch) {
        this.tabJSearch.setProperty(jsearch);
    }

    public void setJTransCoderProperty(UniversalViewProperty encodingProperty) {
        this.tabJTransCoder.setEncodingList(encodingProperty.getEncodingList(), "");
    }

    public JTransCoderProperty getJTransCoderProperty() {
        return this.tabJTransCoder.getProperty();
    }

    public void setJTransCoderProperty(JTransCoderProperty transcoder) {
        this.tabJTransCoder.setProperty(transcoder);
    }

    public boolean getDebugMode() {
        return this.tabVersion.getDebugMode();
    }

    public void setDebugMode(boolean debugMode) {
        this.tabVersion.setDebugMode(debugMode);
    }

    @Override
    public void propertyChange(PropertyChangeEvent evt) {
        this.firePropertyChange(evt.getPropertyName(), evt.getOldValue(), evt.getNewValue());
    }

    public void sendToJTransCoder(String text) {
        BurpUtil.sendToTextHighlight(this);
        this.tabJTransCoder.sendToJTransCoder(text);
    }

    public byte[] receiveFromJTransCoder() {
        return this.tabJTransCoder.receiveFromJTransCoder();
    }

}
