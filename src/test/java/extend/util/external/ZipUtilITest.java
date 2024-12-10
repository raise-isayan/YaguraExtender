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
