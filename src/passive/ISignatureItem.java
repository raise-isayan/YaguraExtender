package passive;

import extend.view.base.MatchItem;

/**
 *
 * @author isayan
 */
public interface ISignatureItem {

    /**
     * @return the enable
     */
    public boolean isSelected();

    /**
     * @param selected the selected to set
     */
    public void setSelected(boolean selected);

    /**
     * @return the issueName
     */
    public String getIssueName();

    /**
     * @return the serverity
     */
    public MatchItem.Severity getServerity();

}
