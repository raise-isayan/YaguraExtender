package extend.util.external;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

/**
 *
 * @author isayan
 */
public class ZipUtil {

    private final static Logger logger = Logger.getLogger(ZipUtil.class.getName());

    public static String getBaseJar(URL url) {
        String path = url.toExternalForm();
        try {
            int fend = path.indexOf('!');
            if (fend >= 0) {
                path = path.substring(0, fend);
            }
            if (path.startsWith("jar:")) {
                path = path.substring("jar:".length());
            }
            File file = new File(new URI(path));
            path = file.getAbsolutePath();
        } catch (URISyntaxException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return path;
    }

    public static FileSystem openZip(Path zipPath) throws IOException {
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

    public static void decompressZip(File zipFile, File outDir, String startsFile) throws IOException {
        try (ZipInputStream zistm = new ZipInputStream(new FileInputStream(zipFile))) {
            ZipEntry zipEntry = null;
            while ((zipEntry = zistm.getNextEntry()) != null) {
                String entryName = zipEntry.getName();
                if (entryName.startsWith(startsFile)) {
                    if (entryName.length() > startsFile.length()) {
                        File outFile = new File(outDir, entryName.substring(startsFile.length()));
                        if (zipEntry.isDirectory()) {
                            outFile.mkdirs();
                        } else {
                            try (BufferedOutputStream bostm = new BufferedOutputStream(new FileOutputStream(outFile))) {
                                byte[] buf = new byte[1024];
                                int len = 0;
                                while ((len = zistm.read(buf)) != -1) {
                                    bostm.write(buf, 0, len);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    public static String[] getSubDirectories(File zipFilePath, String targetPath) throws IOException {
        // ディレクトリ指定として確実に末尾を '/' に揃える
        String formattedPrefix = targetPath.endsWith("/") ? targetPath : targetPath + "/";
        Set<String> dirNames = new TreeSet<>();
        try (ZipFile zipFile = new ZipFile(zipFilePath)) {
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String entryName = entry.getName();
                if (entryName.startsWith(formattedPrefix) && entryName.length() > formattedPrefix.length()) {
                    String relativePath = entryName.substring(formattedPrefix.length());
                    int slashIndex = relativePath.indexOf('/');
                    if (slashIndex != -1) {
                        String subDirName = relativePath.substring(0, slashIndex);
                        dirNames.add(subDirName);
                    }
                }
            }
        }
        return dirNames.toArray(new String[0]);
    }
}
