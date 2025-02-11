package yagura.dynamic;

import java.io.IOException;
import java.security.SecureClassLoader;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;
import javax.tools.DiagnosticListener;
import javax.tools.FileObject;
import javax.tools.ForwardingJavaFileManager;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.JavaFileObject.Kind;

public class RuntimeClassFileManager extends ForwardingJavaFileManager {

    private final static Logger logger = Logger.getLogger(RuntimeClassFileManager.class.getName());

    /**
     * クラス名とコンパイル済みクラスのマップ
     */
    private final Map<String, RuntimeClassObject> objects = new HashMap<>();

    /**
     * クラスローダ
     */
    private ClassLoader classLoader = null;

    /**
     * インスタンスを生成する。
     *
     * @param compiler
     * @param listener
     */
    public RuntimeClassFileManager(JavaCompiler compiler, DiagnosticListener listener) {
        super(compiler.getStandardFileManager(listener, null, null));
    }

    /**
     * 出力用ファイルオブジェクトを取得する。
     *
     * @param location
     * @param className
     * @param kind
     * @param sibling
     * @return
     * @throws java.io.IOException
     */
    @Override
    public JavaFileObject getJavaFileForOutput(Location location, String className, Kind kind, FileObject sibling) throws IOException {
        RuntimeClassObject ret = new RuntimeClassObject(className, kind);
        this.objects.put(className, ret);
        return ret;
    }

    /**
     * JavaObject。
     * @param className
     * @return
     */
    public boolean hasJavaObject(String className) {
        return this.objects.get(className) != null;
    }

    /**
     * JavaObjectを削除する。
     * @param className
     */
    public void removeJavaObject(String className) {
        this.objects.remove(className);
    }

    /**
     * JavaObjectをクリアする。
     */
    public void clearJavaObject() {
        this.objects.clear();
    }

    /**
     * クラスローダーを取得する。
     *
     * @param location
     * @return
     */
    @Override
    public ClassLoader getClassLoader(Location location) {
        if (this.classLoader == null) {
            this.classLoader = new InnerClassLoader(this.getClass().getClassLoader());
        }
        return this.classLoader;
    }

    /**
     * クラスローダ(内部クラス)
     */
    class InnerClassLoader extends SecureClassLoader {

        /**
         * インスタンスを生成する。
         *
         * @param parent
         */
        public InnerClassLoader(ClassLoader parent) {
            super(parent);
        }

        /**
         * クラスを検索する。
         * @param name
         * @return
         */
        @Override
        protected Class findClass(String name) throws ClassNotFoundException {
            Class defineClass = null;
            RuntimeClassObject obj = RuntimeClassFileManager.this.objects.get(name);
            if (obj == null) {
                defineClass = this.getClass().getClassLoader().loadClass(name);
            } else {
                defineClass = obj.getDefinedClass();
                if (defineClass == null) {
                    byte[] arr = obj.toByteArray();
                    defineClass = super.defineClass(name, arr, 0, arr.length);
                    obj.setDefinedClass(defineClass);
                }
            }
            return defineClass;
        }
    }

}
