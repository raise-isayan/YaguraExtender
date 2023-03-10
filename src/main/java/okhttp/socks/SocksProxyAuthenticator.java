package okhttp.socks;

import java.net.Authenticator;
import java.net.PasswordAuthentication;

public class SocksProxyAuthenticator extends Authenticator {

    private final ThreadLocal<PasswordAuthentication> credentials = new ThreadLocal<>();

    private SocksProxyAuthenticator() {
    }

    private static class SingletonHolder {
        private static final SocksProxyAuthenticator instance = new SocksProxyAuthenticator();
    }

    public static final SocksProxyAuthenticator getInstance() {
        return SingletonHolder.instance;
    }

    public void setCredentials(PasswordAuthentication socksAuthentication) {
        SocksProxyAuthenticator authenticator = SocksProxyAuthenticator.getInstance();
        Authenticator.setDefault(authenticator);
        authenticator.credentials.set(socksAuthentication);
    }

    public static void clearCredentials() {
        SocksProxyAuthenticator authenticator = SocksProxyAuthenticator.getInstance();
        Authenticator.setDefault(authenticator);
        authenticator.credentials.set(null);
    }

    @Override
    public PasswordAuthentication getPasswordAuthentication() {
        return credentials.get();
    }
}
