package yagura.model;

import com.google.gson.annotations.Expose;
import extension.burp.IPropertyConfig;
import extension.helpers.json.JsonUtil;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import yagura.Config;

/**
 *
 * @author isayan
 */
public class LoggingProperty implements IPropertyConfig {

    public final static String LOGGING_PROPERTY = "loggingProperty";

    private final static String DEFAULT_LOG_TIMESTAMP_FORMAT = "yyyyMMdd HH:mm:ss";
    private final static String DEFAULT_LOG_DIR_FORMAT = "yyyyMMdd";

    @Expose
    private boolean compress = false;

    /**
     * @return the compress
     */
    public boolean isCompress() {
        return compress;
    }

    /**
     * @param compress the compress to set
     */
    public void setCompress(boolean compress) {
        this.compress = compress;
    }

    @Expose
    private boolean autoLogging = false;

    public boolean isAutoLogging() {
        return this.autoLogging;
    }

    public void setAutoLogging(boolean autoLogging) {
        this.autoLogging = autoLogging;
    }

    @Expose
    private String logBaseDir = Config.getUserDirPath();

    public String getBaseDir() {
        return this.logBaseDir;
    }

    public void setBaseDir(String logBaseDir) {
        this.logBaseDir = logBaseDir;
    }

    @Expose
    private int logFileLimitSize = 0;

    public int getLogFileLimitSize() {
        return this.logFileLimitSize;
    }

    public void setLogFileLimitSize(int logFileLimitSize) {
        this.logFileLimitSize = logFileLimitSize;
    }

    /**
     * @return the logFileLimitSize
     */
    public long getLogFileByteLimitSize() {
        return this.logFileLimitSize * 1024L * 1024L;
    }

    @Expose
    private boolean proxyLog = true;

    public boolean isProxyLog() {
        return this.proxyLog;
    }

    public void setProxyLog(boolean proxyLog) {
        this.proxyLog = proxyLog;
    }

    @Expose
    private boolean toolLog = true;

    public boolean isToolLog() {
        return this.toolLog;
    }

    public void setToolLog(boolean toolLog) {
        this.toolLog = toolLog;
    }

    @Expose
    private boolean websocketLog = true;

    public boolean isWebSocketLog() {
        return this.websocketLog;
    }

    public void setWebSocketLog(boolean websocketLog) {
        this.websocketLog = websocketLog;
    }

    @Expose
    private String logDirFormat = DEFAULT_LOG_DIR_FORMAT;

    public String getLogDirFormat() {
        return this.logDirFormat;
    }

    public void setLogDirFormat(String logDirFormat) {
        this.logDirFormat = logDirFormat;
    }

    private DateTimeFormatter logTimestampDateFormat = DateTimeFormatter.ofPattern(DEFAULT_LOG_TIMESTAMP_FORMAT);

    @Expose
    private String logTimestampFormat = DEFAULT_LOG_TIMESTAMP_FORMAT;

    public String getLogTimestampFormat() {
        return this.logTimestampFormat;
    }

    public void setLogTimestampFormat(String logTimestampFormat) {
        this.logTimestampFormat = logTimestampFormat;
        this.logTimestampDateFormat = DateTimeFormatter.ofPattern(logTimestampFormat);
    }

    public DateTimeFormatter getLogTimestampDateFormat() {
        return this.logTimestampDateFormat;
    }

    /**
     *
     * @return タイムスタンプ
     */
    public synchronized String getCurrentLogTimestamp() {
        DateTimeFormatter format = this.getLogTimestampDateFormat();
        return format.format(ZonedDateTime.now());
    }

    @Expose
    private boolean excludeFilter = false;

    public boolean isExclude() {
        return this.excludeFilter;
    }

    public void setExclude(boolean excludeFilter) {
        this.excludeFilter = excludeFilter;
    }

    @Expose
    private String excludeFilterExtension = "gif,jpg,png,css,ico";

    public String getExcludeExtension() {
        return this.excludeFilterExtension;
    }

    public void setExcludeExtension(String excludeFilterExtension) {
        this.excludeFilterExtension = excludeFilterExtension;
    }

    @Expose
    private boolean warnClosingTemporaryProject = false;

    /**
     * @return the warnClosingTemporaryProject
     */
    public boolean isWarnClosingTemporaryProject() {
        return warnClosingTemporaryProject;
    }

    /**
     * @param warnClosingTemporaryProject the warnClosingTemporaryProject to set
     */
    public void setWarnClosingTemporaryProject(boolean warnClosingTemporaryProject) {
        this.warnClosingTemporaryProject = warnClosingTemporaryProject;
    }

    @Expose
    private int popupTime = 3000;

    /**
     * @return the popupTime
     */
    public int getPopupTime() {
        return popupTime;
    }

    /**
     * @param popupTime the popupTime to set
     */
    public void setPopupTime(int popupTime) {
        this.popupTime = popupTime;
    }

    public void setProperty(LoggingProperty property) {
        this.setAutoLogging(property.isAutoLogging());
        this.setBaseDir(property.getBaseDir());
        this.setLogFileLimitSize(property.getLogFileLimitSize());
        this.setProxyLog(property.isProxyLog());
        this.setToolLog(property.isToolLog());
        this.setWebSocketLog(property.isWebSocketLog());
        this.setLogDirFormat(property.getLogDirFormat());
        this.setLogTimestampFormat(property.getLogTimestampFormat());
        this.setExclude(property.isExclude());
        this.setExcludeExtension(getExcludeExtension());
        this.setWarnClosingTemporaryProject(property.isWarnClosingTemporaryProject());
        this.setPopupTime(property.getPopupTime());
        this.setCompress(property.isCompress());
    }

    @Override
    public String getSettingName() {
        return LOGGING_PROPERTY;
    }

    @Override
    public void saveSetting(String value) {
        LoggingProperty property = JsonUtil.jsonFromString(value, LoggingProperty.class, true);
        this.setProperty(property);
    }

    @Override
    public String loadSetting() {
        return JsonUtil.jsonToString(this, true);
    }

    @Override
    public String defaultSetting() {
        LoggingProperty property = new LoggingProperty();
        return JsonUtil.jsonToString(property, true);
    }

}
