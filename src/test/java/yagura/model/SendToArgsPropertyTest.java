package yagura.model;

import extension.helpers.ConvertUtil;
import java.util.List;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
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
public class SendToArgsPropertyTest {

    public SendToArgsPropertyTest() {
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
    public void testDefaultProperties() {
        System.out.println("testDefaultProperties");
        SendToArgsProperty sendtoArgs = new SendToArgsProperty();
        Properties prop = sendtoArgs.getProperties();
        assertEquals(false, ConvertUtil.parseBooleanDefault(prop.getProperty("SendToArgs.useOverride"), false));
        assertEquals("[]", prop.getProperty("SendToArgs.argsList"));
        {
            SendToArgsProperty resultArgs = new SendToArgsProperty();
            resultArgs.setProperties(prop);
            assertEquals(false, resultArgs.isUseOverride());
            List<String> args = resultArgs.getArgsList();
            assertEquals(0, args.size());
        }
    }

    /**
     * Test of extractLinePart method, of class SendToParameterProperty.
     */
    @Test
    public void testProperties() {
        System.out.println("testProperties");
        SendToArgsProperty sendtoArgs = new SendToArgsProperty();
        sendtoArgs.setUseOverride(true);
        sendtoArgs.setArgsList(List.of("aaa","b\"bb","e,ee"));
        Properties prop = sendtoArgs.getProperties();
        assertEquals(true, ConvertUtil.parseBooleanDefault(prop.getProperty("SendToArgs.useOverride"), false));
        assertEquals("[\"aaa\",\"b\\\"bb\",\"e,ee\"]", prop.getProperty("SendToArgs.argsList"));
        prop.list(System.out);
        {
            SendToArgsProperty resultArgs = new SendToArgsProperty();
            resultArgs.setProperties(prop);
            assertEquals(true, resultArgs.isUseOverride());
            List<String> args = resultArgs.getArgsList();
            assertEquals("aaa", args.get(0));
            assertEquals("b\"bb", args.get(1));
            assertEquals("e,ee", args.get(2));
        }
    }

    @Test
    public void testArgs() {
        String [] formats = new String[] { "host=%H", "port=%P", "%T", "%U", "%A", "%Q", "%C", "%M", "%S","%F","%R","%E", "%B", "%N", "%%" } ;
            for (int i = 0; i < formats.length; i++) {
                StringBuilder buff = new StringBuilder();
                Pattern p = Pattern.compile("%([HPTUAQCMSFRN%])");
                Matcher m = p.matcher(formats[i]);
                while (m.find()) {
                    String opt = m.group(1);
                    String replace = m.group(0);
                    switch (opt.charAt(0)) {
                        case 'H': // %H: will be replaced with the host
                        {
                            replace = "www.example.com";
                            break;
                        }
                        case 'P': // %P: will be replaced with the port
                        {
                            replace = "8080";
                            break;
                        }
                        case 'T': // %T: will be replaced with the protocol
                        {
                            replace = "https";
                            break;
                        }
                        case 'U': // %U: will be replaced with the url
                        {
                            replace = "https://wwww.example.com/test?query";
                            break;
                        }
                        case 'A': // %A: will be replaced with the url path
                        {
                            replace = "/test";
                            break;
                        }
                        case 'Q': // %Q: will be replaced with the url query
                        {
                            replace = "query";
                            break;
                        }
                        case 'C': // %C: will be replaced with the cookies
                        {
                            replace = "Cookie: test=test;";
                            break;
                        }
                        case 'M': // %M: will be replaced with the HTTP-method
                        {
                            replace = "GET";
                            break;
                        }
                        case 'S': // %S: will be replaced with the selected text
                        {
                            replace = "selectedtext";
                            break;
                        }
                        case 'F': // %F: will be replaced with the path to a temporary file containing the selected text
                        {
                            replace = "selectedtext file";
                            break;
                        }
                        case 'R': // %R: will be replaced with the path to a temporary file containing the content of the focused request/response
                        {
                            replace = "request/response";
                            break;
                        }
                        case 'N': // %N: will be replaced with the notes
                        {
                            replace = "notes";
                            break;
                        }
                        case '%': // escape
                        {
                            replace = "%";
                            break;
                        }
                    }
                    m.appendReplacement(buff, replace);
                }
                m.appendTail(buff);
                System.out.println(buff.toString());
            }

    }


}
