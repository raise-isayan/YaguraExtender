package yagura.dynamic;

import burp.api.montoya.sitemap.SiteMapNode;
import burp.api.montoya.utilities.Utilities;

/**
 *
 * @author isayan
 */
public interface BambdaSiteMapFilter extends BambdaFilter {

    public boolean matches(SiteMapNode node, Utilities utilities);

}
