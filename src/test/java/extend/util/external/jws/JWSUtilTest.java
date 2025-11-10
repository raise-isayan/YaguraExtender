package extend.util.external.jws;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import extension.view.base.CaptureItem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 *
 * @author isayan
 */
public class JWSUtilTest {

    public JWSUtilTest() {
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

    private final String JWT_TOKEN00 = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ5b3VyLWFwcCIsInN1YiI6InVzZXIxMjMiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjE3NTU3ODMxNzV9.dqBgwLri4YJt1FIqjjT1Ljn1LWaoDvACfpX1bgSx8bc";

    private final String JWT_COOKIE00 = "Cookie: sessionid=1234567890; token=eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ5b3VyLWFwcCIsInN1YiI6InVzZXIxMjMiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjE3NTU3ODMxNzV9.dqBgwLri4YJt1FIqjjT1Ljn1LWaoDvACfpX1bgSx8bc uid=aabbcceedd";

    private final String JWT_NONE01 = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJtYWluIjoieHh4eHh4Iiwic3ViIjoi44OG44K544OIIn0.";

    /* secret */
    private final String JWT_TOKEN01 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJtYWluIjoieHh4eHh4Iiwic3ViIjoi44OG44K544OIIn0.IjbkfaSdmROAC0MeW40lJo4s_KoX0VgF0vogsXygNNc";

    @Test
    public void testFindToken()
    {
        System.out.println("testFindToken");
        final String TOKEN_TOKEN_RESULT = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ5b3VyLWFwcCIsInN1YiI6InVzZXIxMjMiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjE3NTU3ODMxNzV9.dqBgwLri4YJt1FIqjjT1Ljn1LWaoDvACfpX1bgSx8bc";
        {
            CaptureItem[] tokens = JWSUtil.findToken(JWT_TOKEN00);
            for (CaptureItem t : tokens) {
                System.out.println("token:" + t.getCaptureValue());
                System.out.println("start:" + t.start());
                System.out.println("end:" + t.end());
            }
            assertEquals(1, tokens.length);
            assertEquals(TOKEN_TOKEN_RESULT, tokens[0].getCaptureValue());
        }
        {
            CaptureItem[] tokens = JWSUtil.findToken(JWT_COOKIE00);
            for (CaptureItem t : tokens) {
                System.out.println("token:" + t.getCaptureValue());
                System.out.println("start:" + t.start());
                System.out.println("end:" + t.end());
            }
            assertEquals(1, tokens.length);
            assertEquals(TOKEN_TOKEN_RESULT, tokens[0].getCaptureValue());
        }
    }

    @Test
    public void testContainsTokenFormat()
    {
        System.out.println("testContainsTokenFormat");
        {
            String token = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ5b3VyLWFwcCIsInN1YiI6InVzZXIxMjMiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjE3NTU3ODMxNzV9.dqBgwLri4YJt1FIqjjT1Ljn1LWaoDvACfpX1bgSx8bc";
            assertTrue(JWSUtil.containsTokenFormat(token));
        }
        {
            String token = "Cookie: sessionid=1234567890; token=eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ5b3VyLWFwcCIsInN1YiI6InVzZXIxMjMiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjE3NTU3ODMxNzV9.dqBgwLri4YJt1FIqjjT1Ljn1LWaoDvACfpX1bgSx8bc uid=aabbcceedd";
            assertTrue(JWSUtil.containsTokenFormat(token));
        }
    }

    @Test
    public void testSplitSegment()
    {
        System.out.println("testSplitSegment");
        {
            String token = JWT_TOKEN01;
            String [] segment = JWSUtil.splitSegment(token);
            assertEquals(3, segment.length);
        }
        {
            String token = JWT_NONE01;
            String [] segment = JWSUtil.splitSegment(token);
            assertEquals(3, segment.length);
        }
    }

}
