package yagura.model;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreation;
import burp.api.montoya.websocket.BinaryMessage;
import burp.api.montoya.websocket.TextMessage;
import burp.api.montoya.websocket.WebSocketCreated;
import extension.burp.BurpUtil;
import extension.burp.HttpTarget;
import extension.helpers.ConvertUtil;
import extension.helpers.FileUtil;
import extension.helpers.HttpUtil;
import extension.helpers.StringUtil;
import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import yagura.Config;

/**
 *
 * @author isayan
 */
public class Logging implements Closeable {

    private final static Logger logger = Logger.getLogger(Logging.class.getName());

    private final LoggingProperty loggingProperty = new LoggingProperty();

    public void setLoggingProperty(LoggingProperty loggingProperty) {
        this.loggingProperty.setProperty(loggingProperty);
    }

    public LoggingProperty getLoggingProperty() {
        return this.loggingProperty;
    }

    public final static String LOG_PREFIX = "burp_";
    public final static String LOG_SUFFIX = ".zip";

    private final static Pattern LOG_COUNTER = Pattern.compile(LOG_PREFIX + "\\d{8}(?:_(\\d+))?");

    static int getLogFileCounter(String logFileName) {
        Matcher m = LOG_COUNTER.matcher(logFileName);
        if (m.find()) {
            return ConvertUtil.parseIntDefault(m.group(1), 0);
        } else {
            return -1;
        }
    }

    protected FilenameFilter listLogFileFilter(boolean dirOnly) {
        return new FilenameFilter() {
            @Override
            public boolean accept(File dir, String name) {
                File filter = new File(dir, name);
                final String fileName = getLogFileBaseName(getLoggingProperty().getLogDirFormat());
                return (dirOnly && filter.isDirectory() || !dirOnly) && name.startsWith(fileName);
            }
        };
    }

    protected FilenameFilter listLogFileFilter(boolean dirOnly, String suffix) {
        return new FilenameFilter() {
            @Override
            public boolean accept(File dir, String name) {
                File filter = new File(dir, name);
                final String fileName = getLogFileBaseName(getLoggingProperty().getLogDirFormat());
                return (dirOnly && filter.isDirectory() || !dirOnly) && name.startsWith(fileName) && name.endsWith(suffix);
            }
        };
    }

    protected static FileSystem openZip(Path zipPath) throws IOException {
        Map<String, String> env = Map.of(
                "create", "true",
                "compressionMethod", "DEFLATED"
        );
        try {
            URI zipUri = new URI("jar:file", zipPath.toUri().getPath(), null);
            // Create FileSystem
            return FileSystems.newFileSystem(zipUri, env);
        } catch (URISyntaxException ex) {
            throw new IOException(ex);
        }
    }

    protected FileSystem openFileSystem(Path filePath) throws IOException, URISyntaxException {
        if (getLoggingProperty().isCompress()) {
            return openZip(filePath);
        } else {
            return null;
        }
    }

    /**
     * ログの取得
     *
     * @return ディレクトリ
     * @throws java.io.IOException
     */
    public File mkLog() throws IOException {
        if (this.getLoggingProperty().isCompress()) {
            return mkLogZip(getLoggingProperty().getBaseDir(), getLoggingProperty().getLogDirFormat());
        } else {
            return mkLogDir(getLoggingProperty().getBaseDir(), getLoggingProperty().getLogDirFormat());
        }
    }

    private final static Comparator<File> LOG_FILE_COMPARE = new Comparator<File>() {
        @Override
        public int compare(File o1, File o2) {
            int i1 = getLogFileCounter(o1.getName());
            int i2 = getLogFileCounter(o2.getName());
            return i2 - i1;
        }
    };

    /**
     * ログZipファイルの作成
     *
     * @param logBaseDir 基準ディレクトリ
     * @param logdirFormat フォーマット
     * @return 作成ディレクトリ
     * @throws java.io.IOException
     */
    protected File mkLogZip(String logBaseDir, String logdirFormat) throws IOException {
        File baseDir = new File(logBaseDir);
        File[] logFiles = baseDir.listFiles(listLogFileFilter(false, LOG_SUFFIX));
        if (logFiles == null || (logFiles != null && logFiles.length == 0)) {
            logFiles = new File[]{new File(getLogFileName(logdirFormat, 0) + LOG_SUFFIX)};
        }
        Arrays.sort(logFiles, LOG_FILE_COMPARE);
        File targetZip = logFiles[0];
        int countup = getLogFileCounter(targetZip.getName());
        do {
            String fname = getLogFileName(logdirFormat, countup) + LOG_SUFFIX;
            targetZip = new File(logBaseDir, fname);
            if (!targetZip.exists()) {
                targetZip = FileUtil.createEmptyZip(targetZip);
                break;
            } else {
                if (FileUtil.totalFileSize(targetZip, false) > this.getLoggingProperty().getLogFileByteLimitSize() && this.getLoggingProperty().getLogFileByteLimitSize() > 0) {
                    countup++;
                    continue;
                }
                break;
            }
        } while (true);
        return targetZip;
    }

    /**
     * ログディレクトリの作成
     *
     * @param logBaseDir 基準ディレクトリ
     * @param logdirFormat フォーマット
     * @return 作成ディレクトリ
     * @throws java.io.IOException
     */
    protected File mkLogDir(String logBaseDir, String logdirFormat) throws IOException {
        File baseDir = new File(logBaseDir);
        File[] logFiles = baseDir.listFiles(listLogFileFilter(true));
        if (logFiles == null || (logFiles != null && logFiles.length == 0)) {
            logFiles = new File[]{new File(getLogFileName(logdirFormat, 0))};
        }
        Arrays.sort(logFiles, LOG_FILE_COMPARE);
        File targetDir = logFiles[0];
        int countup = getLogFileCounter(targetDir.getName());
        do {
            String fname = getLogFileName(logdirFormat, countup);
            targetDir = new File(logBaseDir, fname);
            if (!targetDir.exists()) {
                targetDir.mkdir();
                break;
            } else {
                if (FileUtil.totalFileSize(targetDir, false) > this.getLoggingProperty().getLogFileByteLimitSize() && this.getLoggingProperty().getLogFileByteLimitSize() > 0) {
                    countup++;
                    continue;
                }
                break;
            }
        } while (true);
        return targetDir;
    }

    public static String getLogFileBaseName(String logdirFormat) {
        SimpleDateFormat logfmt = new SimpleDateFormat(logdirFormat);
        return LOG_PREFIX + logfmt.format(new java.util.Date());
    }

    public static String getLogFileName(String logdirFormat, int countup) {
        String suffix = (countup == 0) ? "" : String.format("_%d", countup);
        return getLogFileBaseName(logdirFormat) + suffix;
    }

    private FileSystem fs = null;
    private Path logFilePath = null;

    public void open(File logFile) throws IOException {
        try {
            this.logFilePath = logFile.toPath();
            this.fs = openFileSystem(this.logFilePath);
        } catch (URISyntaxException ex) {
            throw new IOException(ex);
        }
    }

    @Override
    public void close() throws IOException {
        if (getLoggingProperty().isCompress()) {
            if (this.fs != null && this.fs.isOpen()) {
                this.fs.close();
            }
        }
    }

    protected Path getLoggingPath(String filename) {
        Path path = null;
        if (this.getLoggingProperty().isCompress()) {
            path = this.fs.getPath(filename);
        } else {
            path = Path.of(this.logFilePath.toString(), filename);
        }
        return path;
    }

    /**
     * プロキシログの出力
     *
     * @param messageId
     * @param httpService
     * @param httpResuest
     * @param httpResponse
     */
    public synchronized void writeProxyMessage(
            int messageId,
            HttpService httpService,
            HttpRequest httpResuest,
            HttpResponse httpResponse) {
        if (httpResponse != null) {
            try {
                boolean includeLog = true;
                String baseLogFileName = Config.getProxyLogMessageName();
                if (getLoggingProperty().isExclude()) {
                    Pattern patternExclude = Pattern.compile(BurpUtil.parseFilterPattern(getLoggingProperty().getExcludeExtension()));
                    Matcher matchExclude = patternExclude.matcher(httpResuest.pathWithoutQuery());
                    if (matchExclude.find()) {
                        includeLog = false;
                    }
                }
                if (includeLog) {
                    Path path = getLoggingPath(baseLogFileName);
                    try (OutputStream ostm = Files.newOutputStream(path, StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {
                        HttpRequestResponse messageInfo = HttpRequestResponse.httpRequestResponse(httpResuest, httpResponse);
                        writeMessage(ostm, messageInfo);
                        ostm.flush();
                    }
                }
            } catch (IOException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            } catch (Exception ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
    }

    /**
     * tool ログの出力
     *
     * @param toolType ツール名
     * @param messageIsRequest リクエストかどうか
     * @param messageInfo メッセージ情報
     */
    public synchronized void writeToolMessage(
            ToolType toolType,
            boolean messageIsRequest,
            HttpRequestResponse messageInfo) {
        try {
            if (!messageIsRequest) {
                String baseLogFileName = Config.getToolLogName(toolType.name());
                boolean includeLog = true;
                if (getLoggingProperty().isExclude()) {
                    Pattern patternExclude = Pattern.compile(BurpUtil.parseFilterPattern(getLoggingProperty().getExcludeExtension()));
                    Matcher matchExclude = patternExclude.matcher(messageInfo.request().url());
                    if (matchExclude.find()) {
                        includeLog = false;
                    }
                }
                if (includeLog) {
                    Path path = getLoggingPath(baseLogFileName);
                    try (OutputStream ostm = Files.newOutputStream(path, StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {
                        writeMessage(ostm, messageInfo);
                        ostm.flush();
                    }
                }
            }
        } catch (IOException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    protected void writeMessage(OutputStream ostm, HttpRequestResponse messageInfo) throws IOException {
        try (BufferedOutputStream fostm = new BufferedOutputStream(ostm)) {
            fostm.write(StringUtil.getBytesRaw("======================================================" + HttpUtil.LINE_TERMINATE));
            fostm.write(StringUtil.getBytesRaw(getLoggingProperty().getCurrentLogTimestamp() + " " + HttpTarget.toURLString(messageInfo.request().httpService()) + HttpUtil.LINE_TERMINATE));
            fostm.write(StringUtil.getBytesRaw("======================================================" + HttpUtil.LINE_TERMINATE));
            if (messageInfo.request() != null) {
                fostm.write(messageInfo.request().toByteArray().getBytes());
                fostm.write(StringUtil.getBytesRaw(HttpUtil.LINE_TERMINATE));
            }
            if (messageInfo.hasResponse()) {
                fostm.write(StringUtil.getBytesRaw("======================================================" + HttpUtil.LINE_TERMINATE));
                fostm.write(messageInfo.response().toByteArray().getBytes());
                fostm.write(StringUtil.getBytesRaw(HttpUtil.LINE_TERMINATE));
            }
            fostm.write(StringUtil.getBytesRaw("======================================================" + HttpUtil.LINE_TERMINATE));
        }
    }

    public void writeWebSocketToolMessage(ToolType toolType, final WebSocketCreated webSocketCreated, TextMessage textMessage) {
        String baseLogFileName = Config.getWebSocketToolLogName(toolType.name());
        this.writeWebSocektMessage(baseLogFileName, webSocketCreated.upgradeRequest(), textMessage);
    }

    public void writeWebSocektToolMessage(ToolType toolType, final WebSocketCreated webSocketCreated, BinaryMessage binaryMessage) {
        String baseLogFileName = Config.getWebSocketToolLogName(toolType.name());
        this.writeWebSocektMessage(baseLogFileName, webSocketCreated.upgradeRequest(), binaryMessage);
    }

//    public void writeWebSocektMessageOriginal(final ProxyWebSocketCreation proxyWebSocketCreation, TextMessage textMessage) {
//        String baseLogFileName = Config.getWebSocketLogMessageName();
//        this.writeWebSocektMessage(baseLogFileName, proxyWebSocketCreation.upgradeRequest(), textMessage);
//    }
    public void writeWebSocketFinalMessage(final ProxyWebSocketCreation proxyWebSocketCreation, TextMessage textMessage) {
        String baseLogFileName = Config.getWebSocketLogFinalMessageName();
        this.writeWebSocektMessage(baseLogFileName, proxyWebSocketCreation.upgradeRequest(), textMessage);
    }

    protected synchronized void writeWebSocektMessage(String baseLogFileName, final HttpRequest upgradeRequest, TextMessage textMessage) {
        try {
            Path path = getLoggingPath(baseLogFileName);
            try (OutputStream ostm = Files.newOutputStream(path, StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {
                writeWebSocektTextMessage(ostm, upgradeRequest, textMessage);
                ostm.flush();
            }
        } catch (IOException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

//    public void writeWebSocketMessageOriginal(final ProxyWebSocketCreation proxyWebSocketCreation, BinaryMessage binaryMessage) {
//        String baseLogFileName = Config.getWebSocketLogMessageName();
//        this.writeWebSocektMessage(baseLogFileName, proxyWebSocketCreation.upgradeRequest(), binaryMessage);
//    }
    public void writeWebSocketFinalMessage(final ProxyWebSocketCreation proxyWebSocketCreation, BinaryMessage binaryMessage) {
        String baseLogFileName = Config.getWebSocketLogFinalMessageName();
        this.writeWebSocektMessage(baseLogFileName, proxyWebSocketCreation.upgradeRequest(), binaryMessage);
    }

    public void writeWebSocektMessage(String baseLogFileName, final HttpRequest upgradeRequest, BinaryMessage binaryMessage) {
        try {
            Path path = getLoggingPath(baseLogFileName);
            try (OutputStream ostm = Files.newOutputStream(path, StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {
                writeWebSocektBinayMessage(ostm, upgradeRequest, binaryMessage);
                ostm.flush();
            }
        } catch (IOException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    protected void writeWebSocektTextMessage(OutputStream ostm, HttpRequest upgradeRequest, TextMessage textMessage) throws IOException {
        try (BufferedOutputStream fostm = new BufferedOutputStream(ostm)) {
            fostm.write(StringUtil.getBytesRaw("======================================================" + HttpUtil.LINE_TERMINATE));
            fostm.write(StringUtil.getBytesRaw(getLoggingProperty().getCurrentLogTimestamp() + " " + textMessage.direction().name() + " " + upgradeRequest.url() + HttpUtil.LINE_TERMINATE));
            fostm.write(StringUtil.getBytesRaw("======================================================" + HttpUtil.LINE_TERMINATE));
            fostm.write(StringUtil.getBytesRaw(textMessage.payload() + HttpUtil.LINE_TERMINATE));
            fostm.write(StringUtil.getBytesRaw("======================================================" + HttpUtil.LINE_TERMINATE));
        }
    }

    protected void writeWebSocektBinayMessage(OutputStream ostm, HttpRequest upgradeRequest, BinaryMessage binaryMessage) throws IOException {
        try (BufferedOutputStream fostm = new BufferedOutputStream(ostm)) {
            fostm.write(StringUtil.getBytesRaw("======================================================" + HttpUtil.LINE_TERMINATE));
            fostm.write(StringUtil.getBytesRaw(getLoggingProperty().getCurrentLogTimestamp() + " " + binaryMessage.direction().name() + " " + upgradeRequest.url() + HttpUtil.LINE_TERMINATE));
            fostm.write(StringUtil.getBytesRaw("======================================================" + HttpUtil.LINE_TERMINATE));
            fostm.write(binaryMessage.payload().getBytes());
            fostm.write(StringUtil.getBytesRaw(HttpUtil.LINE_TERMINATE));
            fostm.write(StringUtil.getBytesRaw("======================================================" + HttpUtil.LINE_TERMINATE));
        }
    }

}
