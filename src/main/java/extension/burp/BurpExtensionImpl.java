package extension.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import extend.util.external.ExtensionHelper;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author isayan
 */
public class BurpExtensionImpl implements BurpExtension {
    private final static Logger logger = Logger.getLogger(BurpExtensionImpl.class.getName());

    private static BurpExtensionImpl extenderImpl;
    private static MontoyaApi montoyaApi;
    private static ExtensionHelper helper = null;
    private BurpVersion burp_version = null;

    @Override
    public void initialize(MontoyaApi api) {
        extenderImpl = this;
        montoyaApi = api;
        helper = new ExtensionHelper(api);
        burp_version = new BurpVersion(api);
    }

    @SuppressWarnings("unchecked")
    public static <T extends BurpExtensionImpl> T getInstance() {
        return (T) extenderImpl;
    }

    public static MontoyaApi getMontoyaApi() {
        return montoyaApi;
    }

    public BurpVersion getBurpVersion() {
        return burp_version;
    }

    public static ExtensionHelper helpers() {
        return helper;
    }

}
