package okhttp.socks;

import java.io.IOException;
import java.net.PasswordAuthentication;
import okhttp3.Interceptor;
import okhttp3.Response;

public class SocksProxyAuthInterceptor implements Interceptor {

    private final PasswordAuthentication authentication;

    public SocksProxyAuthInterceptor(PasswordAuthentication socksAuthentication) {
        this.authentication = socksAuthentication;
    }

    @Override
    public Response intercept(Chain chain) throws IOException {
        SocksProxyAuthenticator.getInstance().setCredentials(this.authentication);
        try {
            return chain.proceed(chain.request());
        } finally {
            SocksProxyAuthenticator.clearCredentials();
        }
    }

}
