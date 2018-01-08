/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package yagura.model;

import yagura.view.AutoResponderProperty;

/**
 *
 * @author isayan
 */
public interface OptionProperty {
    // Encoding
    public EncodingProperty getEncodingProperty();

    public void setEncodingProperty(EncodingProperty encodingProperty);

    // MatchReplace
    public void setMatchReplaceProperty(MatchReplaceProperty matchReplaceProperty);

    public MatchReplaceProperty getMatchReplaceProperty();

    // MatchAlert
    public MatchAlertProperty getMatchAlertProperty();
    
    public void setMatchAlertProperty(MatchAlertProperty matchAlertProperty);

    // AutoResponder
    public AutoResponderProperty getAutoResponderProperty();

    public void setAutoResponderProperty(AutoResponderProperty autoResponderProperty);
    
    // SendTo
    public void setSendToProperty(SendToProperty sendToProperty);

    public SendToProperty getSendToProperty();
        
    // Logging
    public void setLoggingProperty(LoggingProperty loggingProperty);

    public LoggingProperty getLoggingProperty();

    // JSearch
    public JSearchProperty getJSearchProperty();

    public void setJSearchProperty(JSearchProperty filter);

    // JTranscoder
    public JTransCoderProperty getJTransCoderProperty();

    public void setJTransCoderProperty(JTransCoderProperty transcoder);
    
    // all
    public boolean getDebugMode();

    public void setDebugMode(boolean debugMode);
    
}
