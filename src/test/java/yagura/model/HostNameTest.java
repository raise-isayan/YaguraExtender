package yagura.model;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 *
 * @author isayan
 */
public class HostNameTest {
    private final static Logger logger = Logger.getLogger(HostNameTest.class.getName());

    public HostNameTest() {
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
    public void testHostFile() {
        try {
            System.out.println("testHostFile");
            URL hostFile = HostNameTest.class.getResource("/resources/hosts_sample");
            List<String> lines = Files.readAllLines(Path.of(hostFile.toURI()), StandardCharsets.UTF_8);
            HostName hostname = HostName.parseHosts(lines.stream());
            List<HostNameEntry> entryList = hostname.getHostNameEntry();
            for (HostNameEntry entry : entryList) {
                System.out.println("entry:" + (entry.isIPv4() ? "IPv4" : "IPv6") + "\t" + entry.getIPAddress() + "\t" + entry.getHostName());
            }
        } catch (IOException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        } catch (URISyntaxException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

}
