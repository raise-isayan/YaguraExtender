package extension.helpers;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author isayan
 */
public class FileUtil {

    private final static Logger logger = Logger.getLogger(FileUtil.class.getName());

    /**
     * ローテーション可能なファイル名を探す
     *
     * @param dir ディレクトリ
     * @param value
     * @return ローテーションファイル名
     */
    public static boolean existsStartsDir(File dir, final String value) {
        String[] list = dir.list(new FilenameFilter() {

            @Override
            public boolean accept(File dir, String name) {
                return name.startsWith(value);
            }
        });
        return (list.length > 0);
    }

    /**
     * ローテーション可能なファイル名を探す
     *
     * @param dir ディレクトリ
     * @param pattern パターン
     * @return ローテーションファイル名
     */
    public static File rotateFile(File dir, String pattern) {
        int count = 1;
        pattern = pattern.replace("%", "%%");
        pattern += ".%d";
        // 存在しないファイルを探す
        File file = new File(dir, String.format(pattern, count));
        while (file.exists()) {
            count++;
            file = new File(dir, String.format(pattern, count));
        }
        return file;
    }

    public static File tempFile(byte[] buff, String prefix) {
        File file = null;
        FileOutputStream fostm = null;
        try {
            file = File.createTempFile(prefix, ".tmp");
            file.deleteOnExit();
            fostm = new FileOutputStream(file, true);
            fostm.write(buff);
        } catch (IOException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        } finally {
            try {
                if (fostm != null) {
                    fostm.close();
                }
            } catch (IOException ex) {
                logger.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
        return file;
    }

    public static byte[] bytesFromFile(File file) throws IOException {
        ByteArrayOutputStream bostm = new ByteArrayOutputStream();
        try (FileInputStream fstm = new FileInputStream(file)) {
            byte[] buff = new byte[1024];
            int len = 0;
            while ((len = fstm.read(buff)) > 0) {
                bostm.write(buff, 0, len);
            }
        }
        return bostm.toByteArray();
    }

    public static File bytesToFile(byte[] bytes, File file) throws IOException {
        ByteArrayInputStream bostm = new ByteArrayInputStream(bytes);
        try (FileOutputStream fstm = new FileOutputStream(file)) {
            byte[] buff = new byte[1024];
            int len = 0;
            while ((len = bostm.read(buff)) > 0) {
                fstm.write(buff, 0, len);
            }
        }
        return file;
    }

    /* InputStream.readAllBytes は JDK 9 からサポート */
    public static byte[] readAllBytes(InputStream stream) throws IOException {
        ByteArrayOutputStream bostm = new ByteArrayOutputStream();
        byte[] buff = new byte[1024];
        int len = 0;
        while ((len = stream.read(buff)) >= 0) {
            bostm.write(buff, 0, len);
        }
        return bostm.toByteArray();
    }

    public static String appendFirstSeparator(String path, String separator) {
        if (path.startsWith(separator)) {
            return path;
        } else {
            return separator + path;
        }
    }

    public static String removeFirstSeparator(String path, String separator) {
        if (path.startsWith(separator)) {
            return path.substring(path.indexOf(separator) + separator.length());
        } else {
            return path;
        }
    }

    public static String appendLastSeparator(String path, String separator) {
        if (path.endsWith(separator)) {
            return path;
        } else {
            return path + separator;
        }
    }

    public static String removeLastSeparator(String path, String separator) {
        if (path.endsWith(separator)) {
            return path.substring(0, path.lastIndexOf(separator));
        } else {
            return path;
        }
    }

}
