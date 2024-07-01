package yagura.model;

import extension.helpers.FileUtil;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 *
 * @author isayan
 */
public class LogfgingTest {

    public LogfgingTest() {
    }

    @BeforeAll
    public static void setUpClass() {
    }

    @AfterAll
    public static void tearDownClass() {
    }

    @BeforeEach
    public void setUp() {
    }

    @AfterEach
    public void tearDown() {
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

    @Test
    public void testDirFile() throws IOException {
        File fileDir = new File(System.getProperty("java.io.tmpdir"));
        System.out.println("dirName:" + fileDir.getName());
        System.out.println("dirPath:" + fileDir.getPath());
    }

    @Test
    public void testDirFileSystem() throws IOException {
        System.out.println("testDirFileSystem");
        File fileDir = new File("C:\\Windows");
        System.out.println("exists:" + fileDir.exists());
        // Create FileSystem
        Path path = Path.of("C:\\Windows\\Temp");
        System.out.println("path:" + path.toString());
        System.out.println("path.name:" + path.getFileName());
        FileSystem fs = path.getFileSystem();
        Iterable<FileStore> list = fs.getFileStores();
        for (var ite = list.iterator(); ite.hasNext(); ) {
            System.out.println("fs:" + ite.next().name());
        }
        Path file = Path.of(path.toString(), "makefile123");
    }

    @Test
    public void testGetLogFileCounter() {
        System.out.println("testGetLogFileCounter");
        assertEquals(-1, Logging.getLogFileCounter("test_20200101"));
        assertEquals(0, Logging.getLogFileCounter("burp_20201201"));
        assertEquals(1, Logging.getLogFileCounter("burp_20210110_1"));
        assertEquals(9, Logging.getLogFileCounter("burp_20210110_9"));
        assertEquals(10, Logging.getLogFileCounter("burp_20250900_10"));
    }

}
