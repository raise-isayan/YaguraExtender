package extension.view.layout;

import java.awt.Component;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.Insets;
import java.awt.LayoutManager;

/**
 *
 * @author isayan
 */
public class VerticalFlowLayout implements LayoutManager {

    private int vgap = 0;

    /**
     * 新しい<code>VerticalFlowLayout</code>の構築をおこないます
     */
    public VerticalFlowLayout() {
        this(0);
    }

    /**
     * 新しい<code>VerticalFlowLayout</code>の構築をおこないます
     *
     * @param vgap コンポーネント間のギャップです。
     */
    public VerticalFlowLayout(int vgap) {
        if (vgap < 0) {
            this.vgap = 0;
        } else {
            this.vgap = vgap;
        }
    }

    /**
     * 指定された名前で、指定されたコンポーネントをレイアウトに追加します。
     *
     * @param name コンポーネントの名前
     * @param comp - 追加されるコンポーネント 未実装です。
     */
    @Override
    public void addLayoutComponent(String name, Component comp) {
    }

    /**
     * 指定されたパネルにコンテナを配置します。
     *
     * @param parent - レイアウトの必要があるコンポーネント
     */
    @Override
    public void layoutContainer(Container parent) {
        Insets insets = parent.getInsets();
        int w = parent.getSize().width - insets.left - insets.right;

        // int h = parent.size().height - insets.top - insets.bottom;
        int numComponents = parent.getComponentCount();

        if (numComponents == 0) {
            return;
        }
        int y = insets.top;
        int x = insets.left;

        for (int i = 0; i < numComponents; ++i) {
            Component c = parent.getComponent(i);

            if (c.isVisible()) {
                Dimension d = c.getPreferredSize();

                c.setBounds(x, y, w, d.height);
                y += d.height + vgap;
            }
        }
    }

    /**
     * 指定された親コンテナにコンポーネントを配置した時のパネルの最小サイズを計算します。
     *
     * @param parent - 配置されるコンポーネント
     * @return サイズ
     */
    @Override
    public Dimension minimumLayoutSize(Container parent) {
        Insets insets = parent.getInsets();
        int maxWidth = 0;
        int totalHeight = 0;
        int numComponents = parent.getComponentCount();

        for (int i = 0; i < numComponents; ++i) {
            Component c = parent.getComponent(i);

            if (c.isVisible()) {
                Dimension cd = c.getMinimumSize();

                maxWidth = Math.max(maxWidth, cd.width);
                totalHeight += cd.height;
            }
        }
        Dimension td = new Dimension(maxWidth + insets.left + insets.right,
                totalHeight + insets.top + insets.bottom
                + vgap * numComponents);

        return td;
    }

    /**
     * レイアウトがリサイズされるときの処理。
     *
     * @param parent - 配置されるコンポーネント
     * @return サイズ
     */
    @Override
    public Dimension preferredLayoutSize(Container parent) {
        Insets insets = parent.getInsets();
        int maxWidth = 0;
        int totalHeight = 0;
        int numComponents = parent.getComponentCount();

        for (int i = 0; i < numComponents; ++i) {
            Component c = parent.getComponent(i);

            if (c.isVisible()) {
                Dimension cd = c.getPreferredSize();

                maxWidth = Math.max(maxWidth, cd.width);
                totalHeight += cd.height;
            }
        }
        Dimension td = new Dimension(maxWidth + insets.left + insets.right,
                totalHeight + insets.top + insets.bottom
                + vgap * numComponents);

        return td;
    }

    /**
     * レイアウトが削除されるときの処理。
     *
     */
    @Override
    public void removeLayoutComponent(Component comp) {
    }
}
