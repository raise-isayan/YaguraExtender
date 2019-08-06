package yagura.model;

import java.util.EventListener;

/**
 *
 * @author isayan
 */
public interface QuickSearchListener extends EventListener {

    public void quickBackPerformed(QuickSearchEvent evt);

    public void quickForwardPerformed(QuickSearchEvent evt);
    
}
