package yagura.model;

import extension.view.base.RegexItem;
import yagura.dynamic.BambdaInterceptAction;

/**
 *
 * @author isayan
 */
public class MatchConditionItem {

    public enum ConditionMode {
        SETTING, BAMBDA
    };

    private boolean selected;

    private ConditionMode mode = ConditionMode.BAMBDA;

    private RegexItem setting;

    private BambdaInterceptAction intercept;

    public MatchConditionItem() {
    }


    public boolean isSelected() {
        return selected;
    }

    public void setSelected(boolean selected) {
        this.selected = selected;
    }

    /**
     * @return the mode
     */
    public ConditionMode getMode() {
        return this.mode;
    }

    /**
     *
     * @param mode
     */
    public void setMode(ConditionMode mode) {
        this.mode = mode;
    }

    /**
     * @return
     */
    public RegexItem getSettings() {
        return this.setting;
    }

    /**
     * @param setting
     */
    public void setSettings(RegexItem setting) {
        this.setting = setting;
    }

    /**
     * @return
     */
    public boolean hasBambdaIntercept() {
        return this.intercept != null;
    }

    /**
     * @return
     */
    public BambdaInterceptAction getBambdaIntercept() {
        return this.intercept;
    }

    /**
     * @param intercept
     */
    public void setBambdaIntercept(BambdaInterceptAction intercept) {
        this.intercept = intercept;
    }

}
