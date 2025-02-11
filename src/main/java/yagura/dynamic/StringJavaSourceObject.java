package yagura.dynamic;

import java.io.IOException;
import java.net.URI;
import java.util.logging.Logger;
import javax.tools.SimpleJavaFileObject;

public class StringJavaSourceObject extends SimpleJavaFileObject {

    private final static Logger logger = Logger.getLogger(StringJavaSourceObject.class.getName());

    /***
     * クラス名
     */
    private final String className;

    /**
     * コンパイル対象となるJavaソースコード
     */
    private final String content;

    /**
     *
     * @param className
     * @param source
     */
    public StringJavaSourceObject(String className, String source) {
        super(URI.create("string:///" + className.replace('.', '/') + Kind.SOURCE.extension), Kind.SOURCE);
        this.className = className;
        this.content = source;
    }

    /**
     * クラス名取得
     *
     * @return
     */
    public String getClassName() {
        return this.className;
    }

    /**
     * ソースコード取得
     *
     * @param ignoreEncodingErrors
     * @return
     * @throws IOException
     */
    @Override
    public CharSequence getCharContent(boolean ignoreEncodingErrors) throws IOException {
        return this.content;
    }

}
