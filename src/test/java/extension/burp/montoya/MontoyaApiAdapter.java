package extension.burp.montoya;

import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.core.Version;

/**
 *
 * @author isayan
 */
public class MontoyaApiAdapter {

    public static class VersionAdapter implements Version {
        final String name;
        final String major;
        final String minor;
        final String build;
        final BurpSuiteEdition edition;

        public VersionAdapter(String name, String major, String minor, String build, BurpSuiteEdition edition) {
            this.name = name;
            this.major = major;
            this.minor = minor;
            this.build = build;
            this.edition = edition;
        }

        @Override
        public String name() {
            return this.name;
        }

        @Override
        public String major() {
            return this.major;
        }

        @Override
        public String minor() {
            return this.minor;
        }

        @Override
        public String build() {
            return this.build;
        }

        @Override
        public BurpSuiteEdition edition() {
            return this.edition;
        }

    }

}
