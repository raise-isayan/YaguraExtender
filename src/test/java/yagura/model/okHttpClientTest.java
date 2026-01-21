package yagura.model;

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
import extension.helpers.ConvertUtil;
import extension.helpers.HttpUtil;
import extension.helpers.StringUtil;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509TrustManager;
import okhttp3.Authenticator;
import okhttp3.Headers;
import okhttp3.HttpUrl;
import okhttp3.Interceptor;
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
import static org.junit.jupiter.api.Assertions.*;

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
            this.server.start();
            final Dispatcher dispatcher = new Dispatcher() {
                @Override
                public MockResponse dispatch(RecordedRequest request) throws InterruptedException {
                    if (request.getPath().equals("/test/")) {
                        return new MockResponse().addHeader("Content-Type", "application/json; " + "charset=utf-8")
                                .setBody("{ \"auth status\":\"OK\" }").setResponseCode(200);
                    }
                    return new MockResponse().setResponseCode(404);
                }
            };
//            server.setDispatcher(dispatcher);
        } catch (IOException ex) {
            fail(ex.getMessage(), ex);
        }
    }

    @AfterEach
    public void tearDown() {
        try {
            this.server.shutdown();
        } catch (IOException ex) {
            fail(ex.getMessage(), ex);
        }
    }

    @Test
    public void testGetRequest() {
        System.out.println("testGetRequest");
        try {
            server.enqueue(new MockResponse().setResponseCode(200)
                    .addHeader("Content-Type: text/html; charset=iso-8859-1")
            );
            URL url = this.server.url("/").url();
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, HttpUtil.trustAllCerts(), new java.security.SecureRandom());
            final OkHttpClient client = new OkHttpClient.Builder()
                    .sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) HttpUtil.trustAllCerts()[0])
                    .hostnameVerifier((hostname, session) -> true)
                    .build();
            Request request = new Request.Builder().url(url).build();
            try (Response response = client.newCall(request).execute()) {
                ResponseBody body = response.body();
                System.out.println(body.string());
            } catch (IOException ex) {
                fail(ex.getMessage(), ex);
            }
        } catch (NoSuchAlgorithmException | KeyManagementException ex) {
            fail(ex.getMessage(), ex);
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
                fail(ex.getMessage(), ex);
            }
        } catch (NoSuchAlgorithmException | KeyManagementException ex) {
            throw new IOException(ex);
        }
    }

    @Test
    public void testSendtoProxy() {
        System.out.println("testSendtoProxy");
        server.enqueue(new MockResponse().setResponseCode(200)
                .addHeader("Content-Type: text/html; charset=iso-8859-1")
        );
        //testGetProxyRequest();
    }

    public void testGetProxyRequest() {
        try {
            String proxyHost = "127.0.0.1";
            int proxyPort = 8888;
            SocketAddress addr = new InetSocketAddress(proxyHost, proxyPort);
            Proxy proxy = new Proxy(Proxy.Type.HTTP, addr);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, HttpUtil.trustAllCerts(), new java.security.SecureRandom());
            final OkHttpClient client = new OkHttpClient.Builder()
                    .sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) HttpUtil.trustAllCerts()[0])
                    .hostnameVerifier((hostname, session) -> true)
                    .proxy(proxy)
                    .build();
            {
                Request request = new Request.Builder().url("https://www.example.com/").build();
                try (Response response = client.newCall(request).execute()) {
                    ResponseBody body = response.body();
                    System.out.println(body.string());
                } catch (IOException ex) {
                    fail(ex.getMessage(), ex);
                }
            }
            {
                Request request = new Request.Builder().url("http://www.example.com/").build();
                try (Response response = client.newCall(request).execute()) {
                    ResponseBody body = response.body();
                    System.out.println(body.string());
                } catch (IOException ex) {
                    fail(ex.getMessage(), ex);
                }
            }
        } catch (NoSuchAlgorithmException | KeyManagementException ex) {
            fail(ex.getMessage(), ex);
        }
    }

    public void testGetAuthRequest(Authenticator authenticator) {
        try {
            String proxyHost = "127.0.0.1";
            int proxyPort = 8888;
            SocketAddress addr = new InetSocketAddress(proxyHost, proxyPort);
            Proxy proxy = new Proxy(Proxy.Type.HTTP, addr);

            final Map<String, CachingAuthenticator> authCache = new ConcurrentHashMap<>();
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, HttpUtil.trustAllCerts(), new java.security.SecureRandom());
            final OkHttpClient client = new OkHttpClient.Builder()
                    .sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) HttpUtil.trustAllCerts()[0])
                    .authenticator(new CachingAuthenticatorDecorator(authenticator, authCache))
                    .addInterceptor(new AuthenticationCacheInterceptor(authCache))
                    .proxy(proxy)
                    .hostnameVerifier((hostname, session) -> true)
                    .build();
            Request request = new Request.Builder().url("http://127.0.0.1:10000/digest/sendto.php?mode=sendto").build();
            try (Response response = client.newCall(request).execute()) {
                ResponseBody body = response.body();
                System.out.println(body.string());
            } catch (IOException ex) {
                fail(ex.getMessage(), ex);
            }
        } catch (NoSuchAlgorithmException | KeyManagementException ex) {
            fail(ex.getMessage(), ex);
        }
    }

    @Test
    public void testGetDigestAuthRequest() {
        System.out.println("testGetDigestAuthRequest");
        final DigestAuthenticator authenticator = new DigestAuthenticator(new Credentials("test", "testpass"));
        //testGetDigestAuthRequest(authenticator);
    }

    public void testGetDigestAuthRequest(Authenticator authenticator) {
        try {
            String proxyHost = "127.0.0.1";
            int proxyPort = 8888;
            SocketAddress addr = new InetSocketAddress(proxyHost, proxyPort);
            Proxy proxy = new Proxy(Proxy.Type.HTTP, addr);

            server.enqueue(new MockResponse().setResponseCode(401)
                    .addHeader("WWW-Authenticate: Digest realm=\"Digest Auth\", nonce=\"3r1OIGP2BQA=f68b23ea2346ed4b7305eb812c7a1e6981d397ee\", algorithm=MD5, qop=\"auth\"")
                    .addHeader("Content-Type: text/html; charset=iso-8859-1")
            );
            server.enqueue(new MockResponse().setResponseCode(200)
                    .addHeader("Authentication-Info: rspauth=\"d3d522ba1474157e9b4321e54731fd52\", cnonce=\"85d8334b9ee29f75\", nc=00000001, qop=auth")
                    .addHeader("Content-Type: text/html; charset=iso-8859-1")
            );

            final Map<String, CachingAuthenticator> authCache = new ConcurrentHashMap<>();
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, HttpUtil.trustAllCerts(), new java.security.SecureRandom());
            final OkHttpClient client = new OkHttpClient.Builder()
                    .sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) HttpUtil.trustAllCerts()[0])
                    .authenticator(new CachingAuthenticatorDecorator(authenticator, authCache))
                    .addInterceptor(new AuthenticationCacheInterceptor(authCache))
                    .proxy(proxy)
                    .hostnameVerifier((hostname, session) -> true)
                    .build();
            Request request = new Request.Builder().url(server.url("/sendto/").url()).build();
            try (Response response = client.newCall(request).execute()) {
                ResponseBody body = response.body();
                System.out.println(body.string());
            } catch (IOException ex) {
                fail(ex.getMessage(), ex);
            }
        } catch (NoSuchAlgorithmException | KeyManagementException ex) {
            fail(ex.getMessage(), ex);
        }
    }

    @Test
    public void testGetBasicRequest() {
        System.out.println("testGetBasicRequest");
        final BasicAuthenticator authenticator = new BasicAuthenticator(new Credentials("test", "testpass"));
//        testGetAuthRequest(authenticator);
    }

    @Test
    public void testGetDigestRequest() {
        System.out.println("testGetDigestRequest");
        final DigestAuthenticator authenticator = new DigestAuthenticator(new Credentials("test", "testpass"));
//        testGetAuthRequest(authenticator);
    }

    final Proxy SOCKS_PROXY = new Proxy(Proxy.Type.SOCKS, InetSocketAddress.createUnresolved("127.0.0.1", 8081));

    @Test
    public void testGetSocksRequest() {
        System.out.println("testGetSocksRequest");
        //testGetSockshRequest();
    }

    public void testGetSockshRequest() {
        OkHttpClient client = new OkHttpClient();
        client.newBuilder().proxy(SOCKS_PROXY);
        Request request = new Request.Builder().url("https://localhost.localdomain:10000/").build();
        try (Response response = client.newCall(request).execute()) {
            ResponseBody body = response.body();
            System.out.println(body.string());
        } catch (IOException ex) {
            fail(ex.getMessage(), ex);
        }
    }

    @Test
    public void testGetSocksProxyAuthInterceptor() {
        System.out.println("testGetSocksProxyAuthInterceptor");
        //testGetSocksProxyAuthInterceptor(new okhttp.socks.SocksProxyAuthInterceptor(new PasswordAuthentication("test3", "testpass3".toCharArray())));
    }

    @Test
    public void testGetSocksProxy() {
        System.out.println("testGetSocksProxy");
//        String proxyHost = "127.0.0.1";
//        int proxyPort = 1080;
//        SocketAddress addr = InetSocketAddress.createUnresolved(proxyHost, proxyPort);
//        Proxy proxy = new Proxy(Proxy.Type.SOCKS, addr);
//        final OkHttpClient client = new OkHttpClient.Builder()
//                .socketFactory(new SocksProxySocketFactory(proxyHost, proxyPort))
//                .build();
//
//        Request request = new Request.Builder().url("http://www.example.com/").build();
//        try (Response response = client.newCall(request).execute()) {
//            ResponseBody body = response.body();
//            System.out.println(body.string());
//        } catch (IOException ex) {
//            fail(ex.getMessage(), ex);
//        }
    }


    private void testGetSocksProxyAuthInterceptor(Interceptor interceptor) {
        try {
            String proxyHost = "127.0.0.1";
            int proxyPort = 1080;
            SocketAddress addr = new InetSocketAddress(proxyHost, proxyPort);
            Proxy proxy = new Proxy(Proxy.Type.SOCKS, addr);

            server.enqueue(new MockResponse().setResponseCode(200).setBody("test body"));

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, HttpUtil.trustAllCerts(), new java.security.SecureRandom());
            final OkHttpClient client = new OkHttpClient.Builder()
                    .sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) HttpUtil.trustAllCerts()[0])
                    .proxy(proxy).addInterceptor(interceptor)
                    .hostnameVerifier((hostname, session) -> true)
                    .build();
            Request request = new Request.Builder().url("http://www.example.com/").build();
            try (Response response = client.newCall(request).execute()) {
                ResponseBody body = response.body();
                System.out.println(body.string());
            } catch (IOException ex) {
                fail(ex.getMessage(), ex);
            }
        } catch (NoSuchAlgorithmException | KeyManagementException ex) {
            fail(ex.getMessage(), ex);
        }
    }

    @Test
    public void testServer() {
        System.out.println("testServer");
        HttpUrl url = server.url("/");
        System.out.println("url:" + url.toString());
        server.enqueue(new MockResponse().setResponseCode(200).setBody("test body"));
        OkHttpClient client = new OkHttpClient();
        final Request request = new Request.Builder().url(url).build();
        try (Response response = client.newCall(request).execute()) {
            ResponseBody body = response.body();
            System.out.println(body.string());
        } catch (IOException ex) {
            fail(ex.getMessage(), ex);
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

    @Test
    public void testThreadLocalAuthenticator() throws InterruptedException {
        System.out.println("testThreadLocalAuthenticator");

        System.out.println("Authenticator before:" + String.valueOf(java.net.Authenticator.getDefault()));

        ExecutorService threadExecutor = Executors.newFixedThreadPool(10);
        Runnable socksAuthThread = new Runnable() {
            @Override
            public void run() {
                try {
                    java.net.Authenticator currentAuthenticator = java.net.Authenticator.getDefault();
                    System.out.println("thread before:" + String.valueOf(currentAuthenticator));
                    PasswordAuthentication passAuth = new PasswordAuthentication("test", "pass".toCharArray());
                    okhttp.socks.SocksProxyAuthenticator socksAuth = okhttp.socks.SocksProxyAuthenticator.getInstance();
                    socksAuth.setCredentials(passAuth);
                    Thread.sleep(5000);
                    currentAuthenticator = java.net.Authenticator.getDefault();
                    System.out.println("thread after:" + String.valueOf(currentAuthenticator));
                } catch (InterruptedException ex) {
                    fail(ex.getMessage(), ex);
                }
            }

        };
        threadExecutor.submit(socksAuthThread);

        System.out.println("socksGetAuthThread");

        Runnable socksGetAuthThread = new Runnable() {
            @Override
            public void run() {
                for (int i = 0; i < 30; i++) {
                    try {
                        java.net.Authenticator currentAuthenticator = java.net.Authenticator.getDefault();
                        System.out.println("thread current:" + String.valueOf(currentAuthenticator));
                        Thread.sleep(100);
                    } catch (InterruptedException ex) {
                        fail(ex.getMessage(), ex);
                    }
                }
            }

        };
        threadExecutor.submit(socksGetAuthThread);
        threadExecutor.awaitTermination(20, TimeUnit.SECONDS);

        System.out.println("Authenticator after:" + String.valueOf(java.net.Authenticator.getDefault()));
    }

    private static class SocksProxySocketFactory extends SocketFactory {

        private final String proxyHost;
        private final int proxyPort;

        public SocksProxySocketFactory(String proxyHost, int proxyPort) {
            this.proxyHost = proxyHost;
            this.proxyPort = proxyPort;
        }

        @Override
        public Socket createSocket() throws IOException {
            Proxy proxy = new Proxy(Proxy.Type.SOCKS, new InetSocketAddress(proxyHost, proxyPort));
            return new Socket(proxy);
        }

        @Override
        public Socket createSocket(String host, int port) throws IOException {
            Socket socket = createSocket();
            socket.connect(new InetSocketAddress(host, port));
            return socket;
        }

        @Override
        public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
            Socket socket = createSocket();
            socket.bind(new InetSocketAddress(localHost, localPort));
            socket.connect(new InetSocketAddress(host, port));
            return socket;
        }

        @Override
        public Socket createSocket(InetAddress host, int port) throws IOException {
            Socket socket = createSocket();
            socket.connect(new InetSocketAddress(host, port));
            return socket;
        }

        @Override
        public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
            Socket socket = createSocket();
            socket.bind(new InetSocketAddress(localAddress, localPort));
            socket.connect(new InetSocketAddress(address, port));
            return socket;
        }
    }
}
