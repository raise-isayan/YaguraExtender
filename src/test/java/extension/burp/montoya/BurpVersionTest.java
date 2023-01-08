package extension.burp.montoya;

import burp.api.montoya.burpsuite.BurpSuite;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.core.Version;
import extension.burp.BurpVersion;
import extension.burp.montoya.MontoyaApiAdapter.VersionAdapter;
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
public class BurpVersionTest {

    public BurpVersionTest() {
    }

    private static final VersionAdapter BURP_VERSION_FREE = new VersionAdapter(
        "Burp Suite Community Edition",
        "2020",
        "9.5",
        "16933",
        BurpSuiteEdition.COMMUNITY_EDITION
    );

    private static final VersionAdapter BURP_VERSION_PRO = new VersionAdapter(
        "Burp Suite Professional Edition",
        "2020",
        "9.5",
        "16933",
        BurpSuiteEdition.PROFESSIONAL
    );

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
     * Test of parseFreeVersion method, of class BurpVersion.
     */
    @Test
    public void testParseFreeVersion() {
        System.out.println("parseFreeVersion");

        MontoyaApiAdapter api = new MontoyaApiAdapter() {
            @Override
            public BurpSuite burpSuite() {
                return new MontoyaApiAdapter.BurpSuiteAdapter() {
                    @Override
                    public Version version() {
                        return BURP_VERSION_FREE;
                    }
                };
            }
        };

        BurpVersion instance = new BurpVersion(api);
        assertEquals("2020", instance.getMajor());
        assertEquals("9.5", instance.getMinor());
        assertEquals("16933", instance.getBuild());
        assertEquals(2020, instance.getMajorVersion());
        assertEquals(9, instance.getMinorVersion());
        assertFalse(instance.isProfessional());
        assertEquals("Burp Suite Community Edition", instance.getProductName());
        assertEquals("Burp Suite Community Edition 2020.9.5", instance.getVersion());
        System.out.println(instance.getBurpConfigHome());
        System.out.println(instance.getBurpConfigFile());

    }


    /**
     * Test of parseProVersion method, of class BurpVersion.
     */
    @Test
    public void testParseProersion() {
        System.out.println("parseProVersion");

        MontoyaApiAdapter api = new MontoyaApiAdapter() {
            @Override
            public BurpSuite burpSuite() {
                return new MontoyaApiAdapter.BurpSuiteAdapter() {
                    @Override
                    public Version version() {
                        return BURP_VERSION_PRO;
                    }
                };
            }
        };
        BurpVersion instance = new BurpVersion(api);
        assertEquals("2020", instance.getMajor());
        assertEquals("9.5", instance.getMinor());
        assertEquals("16933", instance.getBuild());
        assertEquals(2020, instance.getMajorVersion());
        assertEquals(9, instance.getMinorVersion());
        assertTrue(instance.isProfessional());
        assertEquals("Burp Suite Professional Edition", instance.getProductName());
        assertEquals("Burp Suite Professional Edition 2020.9.5", instance.getVersion());

    }

}
