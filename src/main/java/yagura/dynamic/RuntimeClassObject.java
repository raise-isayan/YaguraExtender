package yagura.dynamic;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.util.logging.Logger;
import javax.tools.SimpleJavaFileObject;

/**
 * コンパイルしたクラスを格納するクラス。
 */
public class RuntimeClassObject extends SimpleJavaFileObject {

    private final static Logger logger = Logger.getLogger(RuntimeClassObject.class.getName());

    private final ByteArrayOutputStream value = new ByteArrayOutputStream();

    /**
     * コンパイル済みのクラス
     */
    private Class definedClass = null;

    public RuntimeClassObject(String className, Kind kind) {
        super(URI.create("string:///" + className.replace('.', '/') + kind.extension), kind);
    }

    @Override
    public OutputStream openOutputStream() throws IOException {
        return this.value;
    }

    public byte[] toByteArray() {
        return this.value.toByteArray();
    }

    public Class getDefinedClass() {
        return this.definedClass;
    }

    public void setDefinedClass(Class definedClass) {
        this.definedClass = definedClass;
    }

}
