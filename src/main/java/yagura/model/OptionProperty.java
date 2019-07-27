package yagura.model;

/**
 *
 * @author raise.isayan
 */
public class OptionProperty implements IOptionProperty {

    /**
     * ***********************************************************************
     * Encoding
     * ***********************************************************************
     */
    private final UniversalViewProperty encodingProperty = new UniversalViewProperty();
    
    @Override
    public UniversalViewProperty getEncodingProperty() {
        return this.encodingProperty;
    }

    @Override
    public void setEncodingProperty(UniversalViewProperty encodingProperty) {
        this.encodingProperty.setProperty(encodingProperty);
    }

    /**
     * ***********************************************************************
     * MatchReplace
     * ***********************************************************************
     */
    private final MatchReplaceProperty matchReplaceProperty = new MatchReplaceProperty();

    @Override
    public MatchReplaceProperty getMatchReplaceProperty() {
        return this.matchReplaceProperty;
    }
    
    @Override
    public void setMatchReplaceProperty(MatchReplaceProperty matchReplaceProperty) {
        this.matchReplaceProperty.setProperty(matchReplaceProperty);
    }

    /**
     * ***********************************************************************
     * MatchAlert
     * ***********************************************************************
     */
    private final MatchAlertProperty matchAlertProperty = new MatchAlertProperty();
    
    @Override
    public MatchAlertProperty getMatchAlertProperty() {
        return this.matchAlertProperty;
    }

    @Override
    public void setMatchAlertProperty(MatchAlertProperty matchAlertProperty) {
        this.matchAlertProperty.setProperty(matchAlertProperty);
    }

    /**
     * ***********************************************************************
     * AutoResponder
     * ***********************************************************************
     */
    private final AutoResponderProperty autoResponderProperty = new AutoResponderProperty();
    
    @Override
    public AutoResponderProperty getAutoResponderProperty() {
        return this.autoResponderProperty;
    }

    @Override
    public void setAutoResponderProperty(AutoResponderProperty autoResponderProperty) {
        this.autoResponderProperty.setProperty(autoResponderProperty);
    }

    /**
     * ***********************************************************************
     * SendTo
     * ***********************************************************************
     */
    private final SendToProperty sendToProperty = new SendToProperty();

    @Override
    public SendToProperty getSendToProperty() {
        return this.sendToProperty;
    }
    
    @Override
    public void setSendToProperty(SendToProperty sendtoProperty) {
        this.sendToProperty.setProperty(sendtoProperty);
    }

    /**
     * ***********************************************************************
     * Logging
     * ***********************************************************************
     */
    private final LoggingProperty logProperty = new LoggingProperty();

    @Override
    public LoggingProperty getLoggingProperty() {
        return this.logProperty;
    }
    
    @Override
    public void setLoggingProperty(LoggingProperty loggingProperty) {
        this.logProperty.setProperty(loggingProperty);
    }

    /**
     * ***********************************************************************
     * JSearch
     * ***********************************************************************
     */
    private final JSearchProperty searchProperty = new JSearchProperty();
    
    @Override
    public JSearchProperty getJSearchProperty() {
        return this.searchProperty;
    }

    @Override
    public void setJSearchProperty(JSearchProperty searchProperty) {
        this.searchProperty.setProperty(searchProperty);
    }

    /**
     * ***********************************************************************
     * JTransCoder
     * ***********************************************************************
     */
    private final JTransCoderProperty transcoderProperty = new JTransCoderProperty();
    
    @Override
    public JTransCoderProperty getJTransCoderProperty() {
        return this.transcoderProperty;
    }

    @Override
    public void setJTransCoderProperty(JTransCoderProperty transcoderProperty) {
        this.transcoderProperty.setProperty(transcoderProperty);
    }
    
    /**
     * debugModeの取得
     */
    private boolean debugMode = false;

    @Override
    public boolean getDebugMode() {
        return this.debugMode;
    }

    @Override
    public void setDebugMode(boolean debugMode) {
        this.debugMode = debugMode;
    }

    /**
     * ***********************************************************************
     * OptionProperty
     * ***********************************************************************
     */
    /**
     * @param property
     */
    public void setProperty(IOptionProperty property) {
        this.setEncodingProperty(property.getEncodingProperty());
        this.setMatchReplaceProperty(property.getMatchReplaceProperty());
        this.setAutoResponderProperty(property.getAutoResponderProperty());
        this.setSendToProperty(property.getSendToProperty());
        this.setLoggingProperty(property.getLoggingProperty());
        this.setMatchAlertProperty(property.getMatchAlertProperty());
        this.setJSearchProperty(property.getJSearchProperty());
        this.setDebugMode(property.getDebugMode());
        this.setDebugMode(getDebugMode());
    }
    
}
