package yagura.view;

import burp.IExtensionStateListener;
import burp.ITab;
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
import yagura.model.IOptionProperty;

/**
 *
 * @author isayan
 */
public class TabbetOption extends javax.swing.JTabbedPane implements IOptionProperty, ITab, IExtensionStateListener, PropertyChangeListener {

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

        this.tabUniversalView.addPropertyChangeListener(CJK_VIEW_PROPERTY, this);
        this.tabMatchReplace.addPropertyChangeListener(MATCHREPLACE_PROPERTY, this);
        this.tabMatchAlert.addPropertyChangeListener(MATCHALERT_PROPERTY, this);
//        this.tabAutoResponder.addPropertyChangeListener(AUTO_RESPONDER_PROPERTY, this);
        this.tabSendTo.addPropertyChangeListener(SENDTO_PROPERTY, this);
        this.tabLogging.addPropertyChangeListener(LOGGING_PROPERTY, this);
        this.tabJSearch.addPropertyChangeListener(JSEARCH_FILTER_PROPERTY, this);
        this.tabJTransCoder.addPropertyChangeListener(JTRANS_CODER_PROPERTY, this);
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

    public void setProperty(IOptionProperty property) {
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

    public IOptionProperty getProperty() {
        return this;
    }

    @Override
    public void setEncodingProperty(UniversalViewProperty encProperty) {
        this.tabUniversalView.setEncodingProperty(encProperty);
    }

    @Override
    public UniversalViewProperty getEncodingProperty() {
        return this.tabUniversalView.getEncodingProperty();
    }

    @Override
    public void setMatchReplaceProperty(MatchReplaceProperty matchReplaceProperty) {
        this.tabMatchReplace.setMatchReplaceProperty(matchReplaceProperty);
    }

    @Override
    public MatchReplaceProperty getMatchReplaceProperty() {
        return this.tabMatchReplace.getMatchReplaceProperty();
    }

    @Override
    public void setSendToProperty(SendToProperty sendToProperty) {
        this.tabSendTo.setSendToProperty(sendToProperty);
    }

    @Override
    public SendToProperty getSendToProperty() {
        return this.tabSendTo.getSendToProperty();
    }

    @Override
    public void setLoggingProperty(LoggingProperty loggingProperty) {
        this.tabLogging.setLoggingProperty(loggingProperty);
    }

    @Override
    public LoggingProperty getLoggingProperty() {
        return tabLogging.getLoggingProperty();
    }

    public boolean isLogDirChanged() {
        return this.tabLogging.isLogDirChanged();
    }

    public boolean isHistoryLogInclude() {
        return this.tabLogging.isHistoryLogInclude();
    }

    @Override
    public MatchAlertProperty getMatchAlertProperty() {
        return this.tabMatchAlert.getMatchAlertProperty();
    }

    @Override
    public void setMatchAlertProperty(MatchAlertProperty matchAlertProperty) {
        this.tabMatchAlert.setMatchAlertProperty(matchAlertProperty);
    }

    @Override
    public JSearchProperty getJSearchProperty() {
        return this.tabJSearch.getProperty();
    }

    @Override
    public void setJSearchProperty(JSearchProperty jsearch) {
        this.tabJSearch.setProperty(jsearch);
    }

    public void setJTransCoderProperty(UniversalViewProperty encodingProperty) {
        this.tabJTransCoder.setEncodingList(encodingProperty.getEncodingList(), "");
    }

    @Override
    public JTransCoderProperty getJTransCoderProperty() {
        return this.tabJTransCoder.getProperty();
    }

    @Override
    public void setJTransCoderProperty(JTransCoderProperty transcoder) {
        this.tabJTransCoder.setProperty(transcoder);
    }

    @Override
    public boolean getDebugMode() {
        return this.tabVersion.getDebugMode();
    }

    @Override
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

    @Override
    public void extensionUnloaded() {
        this.tabJTransCoder.extensionUnloaded();
        this.tabJSearch.extensionUnloaded();
    }

}
