package extension.helpers;

import com.burgstaller.okhttp.AuthenticationCacheInterceptor;
import com.burgstaller.okhttp.CachingAuthenticatorDecorator;
import com.burgstaller.okhttp.basic.BasicAuthenticator;
import com.burgstaller.okhttp.digest.CachingAuthenticator;
import com.burgstaller.okhttp.digest.DigestAuthenticator;
import com.burgstaller.okhttp.digest.Credentials;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509TrustManager;
import okhttp3.Authenticator;
import okhttp3.HttpUrl;
import okhttp3.ResponseBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;

import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
/**
 *
 * @author isayan
 */
public class okHttpClientTest {
    private final static Logger logger = Logger.getLogger(okHttpClientTest.class.getName());

    private final MockWebServer server = new MockWebServer();

    public okHttpClientTest() {
    }

    @BeforeAll
    public static void setUpClass() {
    }

    @AfterAll
    public static void tearDownClass() {
    }


    @BeforeEach
    public void setUp() {
        try {
            server.start();
            Dispatcher dispatcher = new Dispatcher() {
                @Override
                public MockResponse dispatch(RecordedRequest request) throws InterruptedException {
                    if (request.getPath().equals("/v1/test/")){
                        return new MockResponse().addHeader("Content-Type", "application/json; " + "charset=utf-8")
                            .setBody("{ \"auth status\":\"OK\" }").setResponseCode(200);
                    }
                    return new MockResponse().setResponseCode(404);
                }
            };
            server.setDispatcher(dispatcher);
        } catch (IOException ex) {
            Logger.getLogger(okHttpClientTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @AfterEach
    public void tearDown() {
        try {
            server.shutdown();
        } catch (IOException ex) {
            Logger.getLogger(okHttpClientTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Test
    public void testGetRequest() {
        System.out.println("testGetRequest");
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null,HttpUtil.trustAllCerts(), new java.security.SecureRandom());
            final OkHttpClient client = new OkHttpClient.Builder()
                    .sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager)HttpUtil.trustAllCerts()[0])
                    .hostnameVerifier((hostname, session) -> true)
                    .build();
            Request request = new Request.Builder().url("https://www.example.com/").build();
            try (Response response = client.newCall(request).execute()) {
                ResponseBody body = response.body();
                System.out.println(body.string());
            } catch (IOException ex) {
                Logger.getLogger(okHttpClientTest.class.getName()).log(Level.SEVERE, null, ex);
            }
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(okHttpClientTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyManagementException ex) {
            Logger.getLogger(okHttpClientTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void testGetAuthRequest(Authenticator authenticator) {
        try {
            final Map<String, CachingAuthenticator> authCache = new ConcurrentHashMap<>();
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null,HttpUtil.trustAllCerts(), new java.security.SecureRandom());
            final OkHttpClient client = new OkHttpClient.Builder()
                .sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager)HttpUtil.trustAllCerts()[0])
                .authenticator(new CachingAuthenticatorDecorator(authenticator, authCache))
                .addInterceptor(new AuthenticationCacheInterceptor(authCache))
                .hostnameVerifier((hostname, session) -> true)
                .build();
            Request request = new Request.Builder().url("https://www.example.com/").build();
            try (Response response = client.newCall(request).execute()) {
                ResponseBody body = response.body();
                System.out.println(body.string());
            } catch (IOException ex) {
                Logger.getLogger(okHttpClientTest.class.getName()).log(Level.SEVERE, null, ex);
            }
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(okHttpClientTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyManagementException ex) {
            Logger.getLogger(okHttpClientTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }


    @Test
    public void testGetBasicRequest() {
        final BasicAuthenticator authenticator = new BasicAuthenticator(new Credentials("username", "pass"));
        testGetAuthRequest(authenticator);
    }

    @Test
    public void testGetDigestRequest() {
        final DigestAuthenticator authenticator = new DigestAuthenticator(new Credentials("username", "pass"));
        testGetAuthRequest(authenticator);
    }

    final Proxy SOCKS_PROXY = new Proxy(Proxy.Type.SOCKS, InetSocketAddress.createUnresolved("127.0.0.1", 8081));

    @Test
    public void testGetSocksRequest() {
        System.out.println("testGetSocksRequest");
        OkHttpClient client = new OkHttpClient();
        client.newBuilder().proxy(SOCKS_PROXY);
        Request request = new Request.Builder().url("https://www.example.com/").build();
        try (Response response = client.newCall(request).execute()) {
            ResponseBody body = response.body();
            System.out.println(body.string());
        } catch (IOException ex) {
            Logger.getLogger(okHttpClientTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Test
    public void testServer() {
        System.out.println("testServer");
        HttpUrl url = server.url("/v1/test/");
        System.out.println("url:" + url.toString());

        OkHttpClient client = new OkHttpClient();
        final Request request = new Request.Builder().url(url).build();
        try (Response response = client.newCall(request).execute()) {
            ResponseBody body = response.body();
            System.out.println(body.string());
        } catch (IOException ex) {
            Logger.getLogger(okHttpClientTest.class.getName()).log(Level.SEVERE, null, ex);
        }


    }


}
