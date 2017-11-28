/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package yagura.model;

import yagura.Config;
import java.text.SimpleDateFormat;

/**
 *
 * @author isayan
 */
public class LoggingProperty {
    private final static String DEFAULT_LOG_TIMESTAMP_FORMAT = "yyyyMMdd HH:mm:ss";
    private final static String DEFAULT_LOG_DIR_FORMAT = "yyyyMMdd";
    private boolean autoLogging = false;
    private String logBaseDir = Config.getUserDir();
    private int logFileLimitSize = 0;
    private boolean proxyLog = true;
    private boolean toolLog = true;
    private String logDirFormat = DEFAULT_LOG_DIR_FORMAT;
    private String logTimestampFormat = DEFAULT_LOG_TIMESTAMP_FORMAT;
    private boolean exludeFilter = false;
    private String exludeFilterExtension = "gif,jpg,png,css,ico";

    public void setAutoLogging(boolean autoLogging) {
        this.autoLogging = autoLogging;
    }

    public void setBaseDir(String logBaseDir) {
        this.logBaseDir = logBaseDir;
    }

    public void setLogFileLimitSize(int logFileLimitSize) {
        this.logFileLimitSize = logFileLimitSize;
    }

    public boolean isAutoLogging() {
        return this.autoLogging;
    }

    public String getBaseDir() {
        return this.logBaseDir;
    }

    public int getLogFileLimitSize() {
        return this.logFileLimitSize;
    }

    /**
     * @return the logFileLimitSize
     */
    public int getLogFileByteLimitSize() {
        return this.logFileLimitSize * 1024 * 1024;
    }

    public void setProxyLog(boolean proxyLog) {
        this.proxyLog = proxyLog;
    }

    public void setToolLog(boolean toolLog) {
        this.toolLog = toolLog;
    }

    public void setLogDirFormat(String logDirFormat) {
        this.logDirFormat = logDirFormat;
    }

    public boolean isProxyLog() {
        return this.proxyLog;
    }

    public boolean isToolLog() {
        return this.toolLog;
    }

    public String getLogDirFormat() {
        return this.logDirFormat;
    }

    private SimpleDateFormat logTimestampDateFormat = new SimpleDateFormat(DEFAULT_LOG_TIMESTAMP_FORMAT);

    public String getLogTimestampFormat() {
        return this.logTimestampFormat;
    }

    public void setLogTimestampFormat(String logTimestampFormat) {
        this.logTimestampFormat = logTimestampFormat;
        this.logTimestampDateFormat = new SimpleDateFormat(logTimestampFormat);       
    }

    public SimpleDateFormat getLogTimestampDateFormat() {
        return this.logTimestampDateFormat;
    }
    
    public boolean isExludeFilter() {
        return this.exludeFilter;
    }

    public void setExludeFilter(boolean exludeFilter) {
        this.exludeFilter = exludeFilter;
    }
   
    public String getExludeFilterExtension() {
        return this.exludeFilterExtension;
    }

    public void setExludeFilterExtension(String exludeFilterExtension) {
        this.exludeFilterExtension = exludeFilterExtension;
    }
    
}
