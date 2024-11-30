package extend.util.external;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 *
 * @author isayan
 */
public class ZipUtilITest {

    public ZipUtilITest() {
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

    @Test
    public void testBaseJar() throws IOException {
        System.out.println("testBaseJar");
        URL url = new URL("file:/resources/help.jar!/images/Extender_Yagura.png");
        System.out.println(url.toExternalForm());
        String result = ZipUtil.getBaseJar(url);
        System.out.println("url =>" + result);
        assertTrue(result.contains("help.jar"));
    }

    @Test
    public void testBaseJar2() throws IOException {
        System.out.println("testBaseJar2");
        URL url = new URL("jar:file:/resources/help.jar!/images/Extender_Yagura.png");
        System.out.println("Protocol:" + url.getProtocol());
        System.out.println("Host:" + url.getHost());
        System.out.println("File:" + url.getFile());
        System.out.println("Path:" + url.getPath());
        System.out.println("UserInfo:" + url.getUserInfo());
        System.out.println("Exterm:" + url.toExternalForm());
        String result = ZipUtil.getBaseJar(url);
        System.out.println("url =>" + result);
        assertTrue(result.contains("help.jar"));
    }

    @Test
    public void testBaseJar3() throws IOException {
        System.out.println("testBaseJar3");
        try {
            URL url = new URL("file:/C:\\Windows\\Temp\\help.jar!/images/Extender_Yagura.png");
            String result = ZipUtil.getBaseJar(url);
            System.out.println("file =>" + result);
        } catch (Exception ex) {
            fail(ex);
        }
    }

    @Test
    public void testBaseJar4() throws IOException {
        System.out.println("testBaseJar4");
        try {
            URL url = new URL("jar:file:/resources/help.jar!/images/Extender_Yagura.png");
            String result = ZipUtil.getBaseJar(url);
            System.out.println("file =>" + result);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    @Test
    public void testDirFile() throws IOException {
        String storeFileName = ZipUtilITest.class.getResource("/resources/help.jar").getPath();
        File zipFile = new File(storeFileName);
        try (ZipInputStream zistm = new ZipInputStream(new FileInputStream(zipFile))) {
            ZipEntry zipEntry = null;
            while ((zipEntry = zistm.getNextEntry()) != null) {
                String f = zipEntry.getName();
                if (f.startsWith("META-INF")) {
                    System.out.println("entry:" + f);
                } else {
                    System.out.println("else:" + f);
                }
            }
        }
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
        for (var ite = list.iterator(); ite.hasNext();) {
            System.out.println("fs:" + ite.next().name());
        }
        Path file = Path.of(path.toString(), "makefile123");
    }

}
