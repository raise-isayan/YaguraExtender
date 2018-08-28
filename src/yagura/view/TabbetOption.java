/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package yagura.view;

import burp.IExtensionStateListener;
import burp.ITab;
import yagura.model.AutoResponderProperty;
import yagura.model.EncodingProperty;
import yagura.model.LoggingProperty;
import yagura.model.MatchAlertProperty;
import yagura.model.MatchReplaceProperty;
import yagura.model.OptionProperty;
import yagura.model.SendToProperty;
import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import javax.swing.JTabbedPane;
import yagura.model.JSearchProperty;
import yagura.model.JTransCoderProperty;

/**
 *
 * @author isayan
 */
public class TabbetOption extends javax.swing.JTabbedPane implements OptionProperty, ITab, PropertyChangeListener, IExtensionStateListener {

    public TabbetOption() {
        super();
        customizeComponents();
    }

    public TabbetOption(int tabPlacement) {
        super(tabPlacement, WRAP_TAB_LAYOUT);
    }

    public TabbetOption(int tabPlacement, int tabLayoutPolicy) {
        super(tabPlacement, tabLayoutPolicy);
    }

    private final EncodingTab tabEncoding = new EncodingTab();
    private final MatchReplaceTab tabMatchReplace = new MatchReplaceTab();
    private final MatchAlertTab tabMatchAlert = new MatchAlertTab();
    private final AutoResponderTab tabAutoResponder = new AutoResponderTab();
    private final SendToTab tabSendTo = new SendToTab();
    private final LoggingTab tabLogging = new LoggingTab();
    private final JSearchTab tabJSearch = new JSearchTab();
    private final JTransCoderTab tabJTransCoder = new JTransCoderTab();
    private final VersionTab tabVersion = new VersionTab();

    @SuppressWarnings("unchecked")
    private void customizeComponents() {
        this.addTab("Encoding", this.tabEncoding);
        this.addTab("MatchReplace", this.tabMatchReplace);
        this.addTab("MatchAlert", this.tabMatchAlert);
        this.addTab("AutoResponder", this.tabAutoResponder);
        this.addTab("SendTo", this.tabSendTo);
        this.addTab("Logging", this.tabLogging);
        this.addTab("JSearch", this.tabJSearch);
        this.addTab("JTransCoder", this.tabJTransCoder);
        this.addTab("Version", this.tabVersion);
        
        this.tabEncoding.addPropertyChangeListener(ENCODING_PROPERTY, this);
        this.tabMatchReplace.addPropertyChangeListener(MATCHREPLACE_PROPERTY, this);
        this.tabMatchAlert.addPropertyChangeListener(MATCHALERT_PROPERTY, this);
        this.tabAutoResponder.addPropertyChangeListener(AUTO_RESPONDER_PROPERTY, this);
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
        return "YaguraExtender";
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
        this.setAutoResponderProperty(property.getAutoResponderProperty());
        this.setMatchAlertProperty(property.getMatchAlertProperty());
        this.setSendToProperty(property.getSendToProperty());
        this.setJSearchProperty(property.getJSearchProperty());
        this.setJTransCoderProperty(property.getJTransCoderProperty());
        // common
        this.setDebugMode(property.getDebugMode());
    }

    public OptionProperty getProperty() {
        return this;
    }

    @Override
    public void setEncodingProperty(EncodingProperty encProperty) {
        this.tabEncoding.setEncodingProperty(encProperty);
    }

    @Override
    public EncodingProperty getEncodingProperty() {
        return this.tabEncoding.getEncodingProperty();
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
    public void setAutoResponderProperty(AutoResponderProperty autoResponderProperty) {
        this.tabAutoResponder.setAutoResponderProperty(autoResponderProperty);
    }

    @Override
    public AutoResponderProperty getAutoResponderProperty() {
        return this.tabAutoResponder.getAutoResponderProperty();
    }
    
    @Override
    public JSearchProperty getJSearchProperty() {
        return this.tabJSearch.getProperty();
    }

    @Override
    public void setJSearchProperty(JSearchProperty jsearch) {
        this.tabJSearch.setProperty(jsearch);
    }
    
    public void setJTransCoderProperty(EncodingProperty encodingProperty) {        
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
        Container container = this.getParent();
        if (container instanceof JTabbedPane) {
            JTabbedPane tabbet = (JTabbedPane)container;
            int index = tabbet.indexOfTab(this.getTabCaption());
            //BurpExtender.errPrintln("\tname u r:" + index);        
            if (index > -1) {
                tabbet.setForegroundAt(index, Color.RED);
            }
            tabbet.repaint();
            tabbet.updateUI();
        }
        this.tabJTransCoder.sendToJTransCoder(text);
//        Class cls = this.getParent().getClass();
//        BurpExtender.errPrintln("name:" + cls.getName());
//        while ((cls = cls.getSuperclass()) != null) {
//            BurpExtender.errPrintln("\tname:" + cls.getName());        
//        }
    }

    public byte [] receiveFromJTransCoder() {
        return this.tabJTransCoder.receiveFromJTransCoder();        
    }

    @Override
    public void extensionUnloaded() {
        this.tabAutoResponder.extensionUnloaded();
    }
        
}
