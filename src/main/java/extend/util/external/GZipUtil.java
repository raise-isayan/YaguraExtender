package extend.util.external;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.zip.GZIPOutputStream;

/**
 *
 * @author isayan
 */
public class GZipUtil {

    /* 空のZIPファイルを作成する */
    public static File createEmptyGZip(File gzipFile) throws IOException {
        try (OutputStream os = Files.newOutputStream(gzipFile.toPath(),
                     StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
             GZIPOutputStream gzos = new GZIPOutputStream(os)) {
        }
        return gzipFile;
    }


}
