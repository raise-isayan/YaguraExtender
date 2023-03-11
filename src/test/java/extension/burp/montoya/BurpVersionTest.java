package extension.burp.montoya;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.burpsuite.BurpSuite;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.core.Version;
import extension.burp.BurpVersion;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

/**
 *
 * @author isayan
 */
public class BurpVersionTest {

    public BurpVersionTest() {
    }

    private MontoyaApi mockApi;
    private BurpSuite burpSuteApi;

    public static final Version BURP_2020_9_5_VERSION_FREE = new  MontoyaApiAdapter.VersionAdapter(
            "Burp Suite Community Edition",
            "2020",
            "9.5",
            "16933",
            BurpSuiteEdition.COMMUNITY_EDITION
    );

    public static final Version BURP_2023_1_1_VERSION_COMMUNITY = new MontoyaApiAdapter.VersionAdapter(
            "Burp Suite Community Edition",
            "2023",
            "1.1",
            "18663",
            BurpSuiteEdition.COMMUNITY_EDITION
    );

    public static final Version BURP_2023_1_2_VERSION_COMMUNITY = new MontoyaApiAdapter.VersionAdapter(
            "Burp Suite Community Edition",
            "2023",
            "1.2",
            "18663",
            BurpSuiteEdition.COMMUNITY_EDITION
    );

    public static final Version BURP_2023_1_3_VERSION_COMMUNITY = new MontoyaApiAdapter.VersionAdapter(
            "Burp Suite Community Edition",
            "2023",
            "1.3",
            "19254",
            BurpSuiteEdition.COMMUNITY_EDITION
    );

    public static final Version BURP_2023_2_1_VERSION_COMMUNITY = new MontoyaApiAdapter.VersionAdapter(
            "Burp Suite Community Edition",
            "2023",
            "2.1",
            "19050",
            BurpSuiteEdition.COMMUNITY_EDITION
    );


    public static final Version BURP_2023_2_2_VERSION_COMMUNITY = new MontoyaApiAdapter.VersionAdapter(
            "Burp Suite Community Edition",
            "2023",
            "2.2",
            "19276",
            BurpSuiteEdition.COMMUNITY_EDITION
    );


    public static final Version BURP_2020_9_5_VERSION_PRO = new  MontoyaApiAdapter.VersionAdapter(
            "Burp Suite Professional Edition",
            "2020",
            "9.5",
            "16933",
            BurpSuiteEdition.PROFESSIONAL
    );

    public static final Version BURP_2023_1_1_VERSION_PRO = new MontoyaApiAdapter.VersionAdapter(
            "Burp Suite Professional",
            "2023",
            "1.1",
            "18663",
            BurpSuiteEdition.PROFESSIONAL
    );

    public static final Version BURP_2023_1_2_VERSION_PRO = new MontoyaApiAdapter.VersionAdapter(
            "Burp Suite Professional",
            "2023",
            "1.2",
            "18945",
            BurpSuiteEdition.PROFESSIONAL
    );

    public static final Version BURP_2023_1_3_VERSION_PRO = new MontoyaApiAdapter.VersionAdapter(
            "Burp Suite Professional",
            "2023",
            "1.3",
            "19254",
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
        MockitoAnnotations.openMocks(this);
        this.mockApi = Mockito.mock(MontoyaApi.class);
        this.burpSuteApi = Mockito.mock(BurpSuite.class);
        Mockito.when(this.mockApi.burpSuite()).thenReturn(this.burpSuteApi);
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
        Mockito.when(this.mockApi.burpSuite().version()).thenReturn(BURP_2020_9_5_VERSION_FREE);
        BurpVersion instance = new BurpVersion(this.mockApi);
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
        Mockito.when(this.mockApi.burpSuite().version()).thenReturn(BURP_2020_9_5_VERSION_PRO);
        BurpVersion instance = new BurpVersion(this.mockApi);
        assertEquals("2020", instance.getMajor());
        assertEquals("9.5", instance.getMinor());
        assertEquals("16933", instance.getBuild());
        assertEquals(2020, instance.getMajorVersion());
        assertEquals(9, instance.getMinorVersion());
        assertTrue(instance.isProfessional());
        assertEquals("Burp Suite Professional Edition", instance.getProductName());
        assertEquals("Burp Suite Professional Edition 2020.9.5", instance.getVersion());

    }

    @Test
    public void testSuiteMontoyaApiVersion() {
        System.out.println("testSuiteMontoyaApiVersion");
        {
            Mockito.when(this.mockApi.burpSuite().version()).thenReturn(BURP_2023_1_1_VERSION_PRO);
            BurpVersion suite = new BurpVersion(this.mockApi);
            assertEquals("Burp Suite Professional", suite.getProductName());
            assertEquals("2023", suite.getMajor());
            assertEquals(2023, suite.getMajorVersion());
            assertEquals("1.1", suite.getMinor());
            assertTrue(suite.isProfessional());
            assertEquals("18663", suite.getBuild());
        }
        {
            Mockito.when(this.mockApi.burpSuite().version()).thenReturn(BURP_2023_2_1_VERSION_COMMUNITY);
            BurpVersion suite = new BurpVersion(this.mockApi);
            assertEquals("Burp Suite Community Edition", suite.getProductName());
            assertEquals("2023", suite.getMajor());
            assertEquals(2023, suite.getMajorVersion());
            assertEquals("2.1", suite.getMinor());
            assertFalse(suite.isProfessional());
            assertEquals("19050", suite.getBuild());
        }
    }

}
