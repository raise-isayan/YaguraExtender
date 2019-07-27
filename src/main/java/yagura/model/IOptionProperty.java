package yagura.model;

/**
 *
 * @author isayan
 */
public interface IOptionProperty {
    public final static String LOAD_CONFIG_PROPERTY = "LoadConfigProperty";
    public final static String CJK_VIEW_PROPERTY = "EncodingProperty";
    public final static String MATCHREPLACE_PROPERTY = "MatchReplaceProperty";
    public final static String MATCHALERT_PROPERTY = "MatchAlertProperty";
    public final static String AUTO_RESPONDER_PROPERTY = "AutoResponderProperty";
    public final static String SENDTO_PROPERTY = "SendToProperty";
    public final static String LOGGING_PROPERTY = "LoggingProperty";
    public final static String JSEARCH_FILTER_PROPERTY = "JSearchFilterProperty";
    public final static String JTRANS_CODER_PROPERTY = "JTransCoderProperty";
    public final static String VERSION_PROPERTY = "VersionProperty";

    // Encoding
    public UniversalViewProperty getEncodingProperty();

    public void setEncodingProperty(UniversalViewProperty encodingProperty);

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
