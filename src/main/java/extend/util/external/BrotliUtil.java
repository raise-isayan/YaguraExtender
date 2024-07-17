package extend.util.external;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.brotli.dec.BrotliInputStream;

/**
 *
 * @author isayan
 */
public class BrotliUtil {

    public static byte[] decompressBrotli(byte[] content) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (BrotliInputStream btis = new BrotliInputStream(new ByteArrayInputStream(content))) {
            try (BufferedOutputStream out = new BufferedOutputStream(baos)) {
                byte[] buf = new byte[1024];
                int size;
                while ((size = btis.read(buf, 0, buf.length)) != -1) {
                    out.write(buf, 0, size);
                }
                out.flush();
            }
        }
        return baos.toByteArray();
    }

}
