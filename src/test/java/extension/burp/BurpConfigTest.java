package extension.burp;

import extension.helpers.FileUtil;
import extension.helpers.StringUtil;
import java.io.File;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;

/**
 *
 * @author isayan
 */
public class BurpConfigTest {

    public BurpConfigTest() {
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

    /**
     * Test of loadCACeart method, of class BurpConfig.
     */
    @Test
    public void testLoadCACeart() throws Exception {
        System.out.println("loadCACeart");
        KeyStore result = BurpConfig.loadCACeart();
        Properties p = System.getProperties();
        Enumeration<String> e = result.aliases();
        while (e.hasMoreElements()) {
            // cacert
            String alias = e.nextElement();
            assertEquals("cacert", alias);
        }
    }

    @Test
    public void testSystemProperty() throws Exception {
        System.out.println("SystemProperty");
        Properties p = System.getProperties();
        p.list(System.out);
    }

    @Test
    public void testUpdateHostnameResolution() throws Exception {
        System.out.println("testUpdateHostnameResolution");
        String configFile = BurpConfigTest.class.getResource("/resources/hostname_resolution.json").getPath();
        String config = StringUtil.getStringRaw(FileUtil.bytesFromFile(new File(configFile)));
        List<BurpConfig.HostnameResolution> hosts = new ArrayList<>();
        hosts.add(new BurpConfig.HostnameResolution(true, "newhost", "192.0.2.11"));
        System.out.println("loadConfig:" + config);
        String updateConfig = BurpConfig.updateHostnameResolution(config, hosts);
        System.out.println("updateConfig:" + updateConfig);
        String removeConfig = BurpConfig.updateHostnameResolution(updateConfig, hosts, true);
        System.out.println("removeConfig:" + removeConfig);
    }

    @Test
    public void testUpdateHostnameResolutionEmpty() throws Exception {
        System.out.println("testUpdateHostnameResolutionEmpty");
        String configFile = BurpConfigTest.class.getResource("/resources/hostname_resolution_empty.json").getPath();
        String config = StringUtil.getStringRaw(FileUtil.bytesFromFile(new File(configFile)));
        List<BurpConfig.HostnameResolution> hosts = new ArrayList<>();
        hosts.add(new BurpConfig.HostnameResolution(true, "newhost", "192.0.2.11"));
        System.out.println("loadConfig:" + config);
        String updateConfig = BurpConfig.updateHostnameResolution(config, hosts);
        System.out.println("updateConfig:" + updateConfig);
        String removeConfig = BurpConfig.updateHostnameResolution(updateConfig, hosts, true);
        System.out.println("removeConfig:" + removeConfig);
    }

}
