package yagura.model;

import java.io.IOException;
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
import okhttp3.Dns;
import okhttp3.OkHttpClient;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;

/**
 *
 * @author isayan
 */
public class ProxyTest {

    private final static Logger logger = Logger.getLogger(ProxyTest.class.getName());

    public ProxyTest() {
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
    public void testDnsHttpClint() {
        System.out.println("testDnsHttpClint");
        OkHttpClient.Builder clientBuilder = new OkHttpClient.Builder();
        clientBuilder.dns(Dns.SYSTEM).build();

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

//            SocketAddress addr = new InetSocketAddress("127.0.0.1", 1080);
//            Proxy proxy = new Proxy(Proxy.Type.SOCKS, addr);
//            ProxySelector staticProxy = new HttpUtil.StaticProxySelector(proxy) {
//                @Override
//                public void connectFailed(URI uri, SocketAddress sa, IOException ex) {
//                    fail();
//                }
//            };
//
//            builder = builder.proxy(staticProxy);
            HttpClient client = builder.build();
            HttpResponse<String> response = client.send(request, BodyHandlers.ofString());
            int statusCode = response.statusCode();
            String bodyMessage = response.body();
            System.out.println(bodyMessage);
        } catch (IOException | InterruptedException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }

    }

}
