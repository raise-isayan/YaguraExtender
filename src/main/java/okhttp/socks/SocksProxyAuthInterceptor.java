package okhttp.socks;

import java.io.IOException;
import java.net.Authenticator;
import java.net.PasswordAuthentication;
import okhttp3.Interceptor;
import okhttp3.Response;

public class SocksProxyAuthInterceptor implements Interceptor {
    private final PasswordAuthentication credentials;

    public SocksProxyAuthInterceptor(PasswordAuthentication credentials) {
        this.credentials = credentials;
    }

    @Override
    public Response intercept(Interceptor.Chain chain) throws IOException {
        synchronized(Authenticator.class) {
            SocksProxyAuthenticator.getInstance().setCredentials(credentials);
            try {
                return chain.proceed(chain.request());
            } finally {
                SocksProxyAuthenticator.resetCredentials();
            }
        }
    }
}