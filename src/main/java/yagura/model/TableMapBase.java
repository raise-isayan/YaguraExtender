package yagura.model;

import java.io.Serializable;

/**
 * テーブルの 1 行に対応する TableMapBase の基底クラス。
 * <p>
 * BeanTableModel が扱えるのは、このクラスを継承し、かつ
 * <b>引数なしの public コンストラクタ</b> を持つクラスです。
 * (引数なしコンストラクタは {@code addRow()} などで新規行を生成する際に使用します)
 */
public interface TableMapBase  {

}
