package yagura.model;

import extension.helpers.HttpUtil;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Redirect;
import java.net.http.HttpClient.Version;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author isayan
 */
public class ProxyTest {

    public ProxyTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    @Test
    public void testHttpClint() {
        try {
            System.out.println("testHttpClint");
            // https://bugs.openjdk.java.net/browse/JDK-8214516

            HttpClient.Builder builder = HttpClient.newBuilder()
                    .version(Version.HTTP_1_1)
                    .followRedirects(Redirect.NORMAL)
                    .connectTimeout(Duration.ofSeconds(10));

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://www.example.com/"))
                    .build();

            SocketAddress addr = new InetSocketAddress("127.0.0.1", 1080);
            Proxy proxy = new Proxy(Proxy.Type.SOCKS, addr);
            ProxySelector staticProxy = new HttpUtil.StaticProxySelector(proxy) {
                @Override
                public void connectFailed(URI uri, SocketAddress sa, IOException ex) {
                    fail();
                }
            };

            builder = builder.proxy(staticProxy);

            HttpClient client = builder.build();
            HttpResponse<String> response = client.send(request, BodyHandlers.ofString());
            int statusCode = response.statusCode();
            String bodyMessage = response.body();
            System.out.println(bodyMessage);
        } catch (IOException ex) {
            Logger.getLogger(ProxyTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InterruptedException ex) {
            Logger.getLogger(ProxyTest.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

}
