package extension.helpers;

import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.burgstaller.okhttp.AuthenticationCacheInterceptor;
import com.burgstaller.okhttp.CachingAuthenticatorDecorator;
import com.burgstaller.okhttp.basic.BasicAuthenticator;
import com.burgstaller.okhttp.digest.CachingAuthenticator;
import com.burgstaller.okhttp.digest.DigestAuthenticator;
import com.burgstaller.okhttp.digest.Credentials;
import extension.burp.HttpTarget;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.SocketAddress;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509TrustManager;
import okhttp3.Authenticator;
import okhttp3.Headers;
import okhttp3.HttpUrl;
import okhttp3.MediaType;
import okhttp3.MultipartBody;
import okhttp3.ResponseBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
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
                    if (request.getPath().equals("/v1/test/")) {
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
            sslContext.init(null, HttpUtil.trustAllCerts(), new java.security.SecureRandom());
            final OkHttpClient client = new OkHttpClient.Builder()
                    .sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) HttpUtil.trustAllCerts()[0])
                    .hostnameVerifier((hostname, session) -> true)
                    .build();
            Request request = new Request.Builder().url("https://www.example.com/").build();
            try (Response response = client.newCall(request).execute()) {
                ResponseBody body = response.body();
                System.out.println(body.string());
            } catch (IOException ex) {
                Logger.getLogger(okHttpClientTest.class.getName()).log(Level.SEVERE, null, ex);
            }
        } catch (NoSuchAlgorithmException | KeyManagementException ex) {
            Logger.getLogger(okHttpClientTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private final Properties extendProperties = new Properties();

    public Properties getExtendProperty() {
        return extendProperties;
    }

    protected void okHttpPostSendto(HttpRequestResponse messageInfo) throws IOException {
        try {
            burp.api.montoya.http.message.requests.HttpRequest httpRequest = messageInfo.request();
            burp.api.montoya.http.message.responses.HttpResponse httpResponse = messageInfo.response();
            HttpService httpService = httpRequest.httpService();
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, HttpUtil.trustAllCerts(), new java.security.SecureRandom());
            final OkHttpClient client = new OkHttpClient.Builder()
                    .sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) HttpUtil.trustAllCerts()[0])
                    .hostnameVerifier((hostname, session) -> true)
                    .build();

            MultipartBody.Builder multipartBuilder = new MultipartBody.Builder()
                    .setType(MultipartBody.FORM) //デフォルトはmultipart/mixedなのでmultipart/form-dataに設定し直す
                    .addFormDataPart("host", httpService.host())
                    .addFormDataPart("port", StringUtil.toString(httpService.port()))
                    .addFormDataPart("protocol", HttpTarget.getProtocol(httpService.secure()))
                    .addFormDataPart("url", httpRequest.url());
            String notes = messageInfo.annotations().notes();
            if (notes != null) {
                multipartBuilder.addFormDataPart("comment", notes);
            }
            HighlightColor color = messageInfo.annotations().highlightColor();
            if (color != null) {
                multipartBuilder.addFormDataPart("highlight", color.name());
            }
            if (httpRequest != null) {
                multipartBuilder.addFormDataPart("request", null, RequestBody.create(httpRequest.toByteArray().getBytes(), MediaType.parse("application/json")));
            }
            if (httpResponse != null) {
                multipartBuilder.addFormDataPart("response", null, RequestBody.create(httpResponse.toByteArray().getBytes(), MediaType.parse("application/json")));
            }
            MultipartBody multipartBody = multipartBuilder.build();

            // 拡張オプションを取得
            Properties prop = getExtendProperty();
            // Authorization

            // Proxy
            String proxyProtocol = prop.getProperty("proxyProtocol", Proxy.Type.DIRECT.name());
            Proxy proxy = Proxy.NO_PROXY;
            if (!Proxy.Type.DIRECT.name().equals(proxyProtocol)) {
                String proxyHost = prop.getProperty("proxyHost", "");
                if (Proxy.Type.HTTP.name().equals(proxyProtocol)) {
                    int proxyPort = ConvertUtil.parseIntDefault(prop.getProperty("proxyPort", "8080"), 8080);
                    SocketAddress addr = new InetSocketAddress(proxyHost, proxyPort);
                    proxy = new Proxy(Proxy.Type.HTTP, addr);
                } else if (Proxy.Type.SOCKS.name().equals(proxyProtocol)) {
                    int proxyPort = ConvertUtil.parseIntDefault(prop.getProperty("proxyPort", "1080"), 1080);
                    SocketAddress addr = new InetSocketAddress(proxyHost, proxyPort);
                    proxy = new Proxy(Proxy.Type.SOCKS, addr);
                }
            }
            String proxyUser = prop.getProperty("proxyUser", "");
            String proxyPasswd = prop.getProperty("proxyPasswd", "");
//            Authenticator authenticator = new Authenticator() {
//                @Override
//                protected PasswordAuthentication getPasswordAuthentication() {
//                    return new PasswordAuthentication(proxyUser, proxyPasswd.toCharArray());
//                }
//            };
//            if (!proxyUser.isEmpty()) {
//                Authenticator.setDefault(authenticator);
//            }

            Request request = new Request.Builder().url("https://www.example.com/").post(multipartBody).build();
            try (Response response = client.newCall(request).execute()) {
                ResponseBody body = response.body();
                System.out.println(body.string());
            } catch (IOException ex) {
                Logger.getLogger(okHttpClientTest.class.getName()).log(Level.SEVERE, null, ex);
            }
        } catch (NoSuchAlgorithmException | KeyManagementException ex) {
            throw new IOException(ex);
        }
    }

    @Test
    public void testPostSendto() {
        System.out.println("testPostSendto");

    }

    public void testGetAuthRequest(Authenticator authenticator) {
        try {
            final Map<String, CachingAuthenticator> authCache = new ConcurrentHashMap<>();
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, HttpUtil.trustAllCerts(), new java.security.SecureRandom());
            final OkHttpClient client = new OkHttpClient.Builder()
                    .sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) HttpUtil.trustAllCerts()[0])
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

    @Test
    public void testHeaderParse() {
        System.out.println("testHeaderParse");
        Headers headers = Headers.of("Version", "510063551", "Content-Type", "application/json; charset=UTF-8");
        for (int i = 0; i < headers.size(); i++) {
            System.out.println(headers.name(i) + ":" + headers.value(i));
        }
        Headers.Builder builder = new Headers.Builder();
        builder.add("Version", "510063551");
        builder.add("Content-Type", "application/json; charset=UTF-8");
        Headers headers2 = builder.build();
        for (int i = 0; i < headers2.size(); i++) {
            System.out.println(headers2.name(i) + ":" + headers2.value(i));
        }
    }

}