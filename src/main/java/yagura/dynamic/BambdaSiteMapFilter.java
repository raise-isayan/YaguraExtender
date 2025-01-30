package yagura.dynamic;

import burp.api.montoya.sitemap.SiteMapNode;
import javax.swing.text.Utilities;

/**
 *
 * @author isayan
 */
public interface BambdaSiteMapFilter {

    public boolean matches(SiteMapNode node, Utilities utilities);

}
