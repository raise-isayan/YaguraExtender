package okhttp.socks;

import extension.helpers.HttpUtil;
import java.net.Authenticator;
import java.net.PasswordAuthentication;

public class SocksProxyAuthenticator extends Authenticator {
    private final ThreadLocal<PasswordAuthentication> credentials = new ThreadLocal<>();
    private final ThreadLocal<Authenticator> saveAuthenticator = new ThreadLocal<>();

    private SocksProxyAuthenticator(){}

    private static class SingletonHolder {
        private static final SocksProxyAuthenticator instance = new SocksProxyAuthenticator();
    }

    public static SocksProxyAuthenticator getInstance() {
        return SingletonHolder.instance;
    }

    public void setCredentials(PasswordAuthentication credentials) {
        SocksProxyAuthenticator authenticator = SocksProxyAuthenticator.getInstance();
        //Authenticator.setDefault(authenticator);
        authenticator.saveAuthenticator.set(HttpUtil.putAuthenticator(authenticator));
        authenticator.credentials.set(credentials);
    }

    public static void resetCredentials() {
        SocksProxyAuthenticator authenticator = SocksProxyAuthenticator.getInstance();
        Authenticator.setDefault(authenticator.saveAuthenticator.get());
        authenticator.credentials.remove();
    }

    @Override
    public PasswordAuthentication getPasswordAuthentication() {
        return credentials.get();
    }
}