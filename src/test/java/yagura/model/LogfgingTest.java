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
        File fileDir = new File("C:\\Windows\\Temp");
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
    public void testZipFileSystem() throws IOException {
        Path zipPath = Path.of("C:\\App\\burp\\burp_20240618.zip");
        System.out.println("pathx:" + zipPath.toUri().getPath());
        FileSystem fs = openZip(zipPath);
        Path p = fs.getPath("test.log");
        System.out.println("pt:" + p.toAbsolutePath());
        try (OutputStream ostm = Files.newOutputStream(p, StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {
            ostm.write("test".getBytes());
        }
        fs.close();
    }


}
