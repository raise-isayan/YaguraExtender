/*/*

 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package yagura.signature;

import java.util.List;
import yagura.model.MatchAlertItem;

/**
 *
 * @author isayan
 */
public class MatchAlertIssue {

    public MatchAlertIssue(MatchAlertItem item, List<MarkIssue> issues) {
        this.item = item;
        this.issues = issues;
    }
    
    private final List<MarkIssue> issues;
    private final MatchAlertItem item;

    public List<MarkIssue> getMarkIssue() {
        return this.issues;
    }
        
    public MatchAlertItem getMatchAlertItem() {
        return this.item;
    }
    
}
