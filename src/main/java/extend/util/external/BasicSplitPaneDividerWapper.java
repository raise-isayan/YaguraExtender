package extend.util.external;

import javax.swing.JButton;
import javax.swing.plaf.basic.BasicSplitPaneDivider;
import javax.swing.plaf.basic.BasicSplitPaneUI;

/**
 *
 * @author isayan
 */
public class BasicSplitPaneDividerWapper extends BasicSplitPaneDivider {

    public BasicSplitPaneDividerWapper(BasicSplitPaneUI ui) {
        super(ui);
        oneTouchExpandableChanged();
    }

    public JButton getLeftBotton() {
        return super.leftButton;
    }

    public JButton getRightBotton() {
        return super.rightButton;
    }


}
