package yagura.model;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import extension.burp.BurpUtil;
import extension.burp.HttpTarget;
import extension.helpers.FileUtil;
import extension.helpers.HttpUtil;
import extension.helpers.StringUtil;
import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileFilter;
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

    /**
     * ログZipファイルの作成
     *
     * @param logBaseDir 基準ディレクトリ
     * @param logdirFormat フォーマット
     * @return 作成ディレクトリ
     * @throws java.io.IOException
     */
    protected static File mkLogZip(String logBaseDir, String logdirFormat) throws IOException {
        String fname = getBaseLogfileName(logdirFormat, 0) + ".zip";
        File logzip = new File(logBaseDir, fname);
        if (logzip.exists()) {
            return logzip;
        }
        else {
            return FileUtil.createEmptyZip(logzip);
        }
    }

    /**
     * ログディレクトリの作成
     *
     * @param logBaseDir 基準ディレクトリ
     * @param logdirFormat フォーマット
     * @return 作成ディレクトリ
     * @throws java.io.IOException
     */
    protected static File mkLogDir(String logBaseDir, String logdirFormat) throws IOException {
        File logdir = null;
        int countup = 0;
        do {
            String fname = getBaseLogfileName(logdirFormat, countup);
            logdir = new File(logBaseDir, fname);
            File lists[] = logdir.listFiles(new FileFilter() {
                @Override
                public boolean accept(File pathname) {
                    return pathname.getName().startsWith(LOG_PREFIX);
                }
            });
            if (lists != null && lists.length == 0) {
                break;
            }
            countup++;
            if (logdir.exists()) {
                // ディレクトリが存在した場合は無条件にログディレクトリの対象にする
                break;
            } else if (logdir.mkdir()) {
                break;
            } else {
                throw new IOException("mkdir error:" + logdir.getAbsolutePath());
            }
        } while (true);
        return logdir;
    }

    public final static String LOG_PREFIX = "burp_";

    public static String getBaseLogfileName(String logdirFormat, int countup) {
        SimpleDateFormat logfmt = new SimpleDateFormat(logdirFormat);
        String suffix = (countup == 0) ? "" : String.format("_%d", countup);
        return LOG_PREFIX + logfmt.format(new java.util.Date()) + suffix;
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

//    protected File rotateLogFile(String baseDir, String baseName) throws IOException {
//        File fname = rotateLogFile(getLoggingProperty().getBaseDir(), Config.getProxyLogMessageName());
//        File fname = rotateLogFile(getLoggingProperty().getBaseDir(), baseLogFileName);
//        if (this.getLoggingProperty().isCompress()) {
//            File fname = new File(baseDir, baseName + ".zip");
//            File renameFile = FileUtil.rotateFile(new File(baseDir), baseName + ".zip");
//            fname.renameTo(renameFile);
//            return fname;
//        } else {
//            File fname = new File(baseName);
//            if (Files.size(fname.toPath()) > getLoggingProperty().getLogFileByteLimitSize()
//                    && getLoggingProperty().getLogFileByteLimitSize() > 0) {
//                File renameFile = FileUtil.rotateFile(mkLogDir(), baseName);
//                fname.renameTo(renameFile);
//            }
//            return fname;
//        }
//    }
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

}
