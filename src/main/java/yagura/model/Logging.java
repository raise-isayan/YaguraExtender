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
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Comparator;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPOutputStream;
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
    public final static String LOG_GZ_SUFFIX = ".gz";

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

    /**
     * ログの取得
     *
     * @return ディレクトリ
     * @throws java.io.IOException
     */
    public File mkLog() throws IOException {
        return mkLogDir(getLoggingProperty().getBaseDir(), getLoggingProperty().getLogDirFormat());
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

//    private FileSystem fs = null;
    private Path logFilePath = null;

    public void open(File logFile) throws IOException {
        this.logFilePath = logFile.toPath();
    }

    @Override
    public void close() throws IOException {
    }

    protected Path getLoggingPath(String filename) {
        Path path = null;
        if (this.getLoggingProperty().isCompress()) {
            path = Path.of(this.logFilePath.toString(), filename + LOG_GZ_SUFFIX);
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
                    try (OutputStream ostm = new AppendLogStream(path, this.getLoggingProperty().isCompress())) {
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
                    try (OutputStream ostm = new AppendLogStream(path, this.getLoggingProperty().isCompress())) {
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
            fostm.write(StringUtil.getBytesRaw(getLoggingProperty().getCurrentLogTimestamp() + " " + "[" + messageInfo.request().httpService().ipAddress() + "]" + " " + HttpTarget.toURLString(messageInfo.request().httpService()) + " " + HttpUtil.LINE_TERMINATE));
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

    //
    // WebSocket
    //
    public void writeWebSocketToolMessage(ToolType toolType, final WebSocketCreated webSocketCreated, TextMessage textMessage) {
        String baseLogFileName = Config.getWebSocketToolLogName(toolType.name());
        this.writeWebSocektMessage(baseLogFileName, webSocketCreated.upgradeRequest(), textMessage);
    }

    public void writeWebSocektToolMessage(ToolType toolType, final WebSocketCreated webSocketCreated, BinaryMessage binaryMessage) {
        String baseLogFileName = Config.getWebSocketToolLogName(toolType.name());
        this.writeWebSocektMessage(baseLogFileName, webSocketCreated.upgradeRequest(), binaryMessage);
    }

    public void writeWebSocketFinalMessage(final ProxyWebSocketCreation proxyWebSocketCreation, TextMessage textMessage) {
        String baseLogFileName = Config.getWebSocketLogFinalMessageName();
        this.writeWebSocektMessage(baseLogFileName, proxyWebSocketCreation.upgradeRequest(), textMessage);
    }

    protected synchronized void writeWebSocektMessage(String baseLogFileName, final HttpRequest upgradeRequest, TextMessage textMessage) {
        try {
            Path path = getLoggingPath(baseLogFileName);
            try (OutputStream ostm = new AppendLogStream(path, this.getLoggingProperty().isCompress())) {
                writeWebSocektTextMessage(ostm, upgradeRequest, textMessage);
                ostm.flush();
            }
        } catch (IOException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    public void writeWebSocketFinalMessage(final ProxyWebSocketCreation proxyWebSocketCreation, BinaryMessage binaryMessage) {
        String baseLogFileName = Config.getWebSocketLogFinalMessageName();
        this.writeWebSocektMessage(baseLogFileName, proxyWebSocketCreation.upgradeRequest(), binaryMessage);
    }

    public void writeWebSocektMessage(String baseLogFileName, final HttpRequest upgradeRequest, BinaryMessage binaryMessage) {
        try {
            Path path = getLoggingPath(baseLogFileName);
            try (OutputStream ostm = new AppendLogStream(path, this.getLoggingProperty().isCompress())) {
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
            fostm.write(StringUtil.getBytesRaw(getLoggingProperty().getCurrentLogTimestamp() + " " + textMessage.direction().name() + " " + "[" + upgradeRequest.httpService().ipAddress() + "]" + " " + upgradeRequest.url() + " " + HttpUtil.LINE_TERMINATE));
            fostm.write(StringUtil.getBytesRaw("======================================================" + HttpUtil.LINE_TERMINATE));
            fostm.write(StringUtil.getBytesRaw(textMessage.payload() + HttpUtil.LINE_TERMINATE));
            fostm.write(StringUtil.getBytesRaw("======================================================" + HttpUtil.LINE_TERMINATE));
        }
    }

    protected void writeWebSocektBinayMessage(OutputStream ostm, HttpRequest upgradeRequest, BinaryMessage binaryMessage) throws IOException {
        try (BufferedOutputStream fostm = new BufferedOutputStream(ostm)) {
            fostm.write(StringUtil.getBytesRaw("======================================================" + HttpUtil.LINE_TERMINATE));
            fostm.write(StringUtil.getBytesRaw(getLoggingProperty().getCurrentLogTimestamp() + " " + binaryMessage.direction().name() + " " + "[" + upgradeRequest.httpService().ipAddress() + "]" + " " + upgradeRequest.url() + " " + HttpUtil.LINE_TERMINATE));
            fostm.write(StringUtil.getBytesRaw("======================================================" + HttpUtil.LINE_TERMINATE));
            fostm.write(binaryMessage.payload().getBytes());
            fostm.write(StringUtil.getBytesRaw(HttpUtil.LINE_TERMINATE));
            fostm.write(StringUtil.getBytesRaw("======================================================" + HttpUtil.LINE_TERMINATE));
        }
    }

    public static class AppendLogStream extends OutputStream implements Closeable {

        private final Path path;
        private final int flushThresholdBytes;
        private final boolean compress;
        private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        public AppendLogStream(Path path, boolean compress) throws IOException {
            this(path, compress, -1);
        }

        public AppendLogStream(Path path, boolean compress, int flushThresholdBytes) throws IOException {
            this.path = path;
            this.flushThresholdBytes = flushThresholdBytes;
            this.compress = compress;
            createEmptyFile();
        }

        /**
         * 新規作成。compress=trueなら空の有効なgzip、falseなら空のテキストファイル
         */
        private void createEmptyFile() throws IOException {
            if (this.compress) {
                try (OutputStream os = Files.newOutputStream(this.path,
                        StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
                    try (GZIPOutputStream gzos = new GZIPOutputStream(os)) {
                    }
                }
            } else {
                Files.newOutputStream(this.path,
                        StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING).close();
            }
        }

        @Override
        public synchronized void write(byte[] data) throws IOException {
            this.buffer.write(data);
            if (0 <= this.flushThresholdBytes && this.flushThresholdBytes <= this.buffer.size()) {
                flush();
            }
        }

        @Override
        public void write(int b) throws IOException {
            this.buffer.write(b);
            if (0 <= this.flushThresholdBytes && this.flushThresholdBytes <= this.buffer.size()) {
                flush();
            }
        }

        /**
         * バッファの中身をファイル末尾に書き出す
         */
        @Override
        public void flush() throws IOException {
            if (this.buffer.size() == 0) {
                return;
            }
            if (this.compress) {
                // 新しいgzipメンバーとして追記
                try (OutputStream os = Files.newOutputStream(this.path, StandardOpenOption.APPEND)) {
                    try (GZIPOutputStream gzos = new GZIPOutputStream(os)) {
                        buffer.writeTo(gzos);
                    }
                }
            } else {
                // プレーンテキストとしてそのまま追記
                try (OutputStream os = Files.newOutputStream(this.path, StandardOpenOption.APPEND)) {
                    this.buffer.writeTo(os);
                }
            }
            this.buffer.reset();
        }

        @Override
        public synchronized void close() throws IOException {
            flush();
            this.buffer.close();
        }

    }

}
