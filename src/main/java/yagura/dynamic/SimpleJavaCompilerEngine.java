package yagura.dynamic;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import javax.tools.DiagnosticListener;
import javax.tools.JavaCompiler;
import javax.tools.JavaCompiler.CompilationTask;
import javax.tools.JavaFileObject;
import javax.tools.ToolProvider;

/**
 *
 * @author isayan
 */
public class SimpleJavaCompilerEngine {

    private final static Logger logger = Logger.getLogger(SimpleJavaCompilerEngine.class.getName());

    private final static String PATH_SEPARATOR = System.getProperty("path.separator");

    // Javaコンパイラを取得する。
    private final JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();

    private final RuntimeClassFileManager fileManager;

    public SimpleJavaCompilerEngine() {
        this.fileManager = new RuntimeClassFileManager(this.compiler, null);
    }

    public SimpleJavaCompilerEngine(DiagnosticListener<? super JavaFileObject> managerListener) {
        this.fileManager = new RuntimeClassFileManager(this.compiler, managerListener);
    }

    public RuntimeClassFileManager getFileManager() {
        return this.fileManager;
    }

    public boolean hasDefineClass(String className) throws ClassNotFoundException {
        return this.fileManager.hasJavaObject(className);
    }

    public Class getDefineClass(String className) throws ClassNotFoundException {
        return (Class) this.fileManager.getClassLoader(null).loadClass(className);
    }

    public void removeDefineClass(String className) {
        this.fileManager.removeJavaObject(className);
    }

    /**
     * クラスパス
     *
     * @return
     */
    public String getClassPath() {
        StringBuilder classPathBuffer = new StringBuilder();
        for (String s : this.getClassLoactions(null)) {
            if (classPathBuffer.length() > 0) {
                classPathBuffer.append(PATH_SEPARATOR);
            }
            classPathBuffer.append(s);
        }
        for (String s : this.extensionLocation) {
            if (classPathBuffer.length() > 0) {
                classPathBuffer.append(PATH_SEPARATOR);
            }
            classPathBuffer.append(s);
        }
        return classPathBuffer.toString();
    }

    /**
     * コンパイル実行
     *
     * @param className
     * @param source
     * @param listener
     * @return
     */
    public Class compile(String className, String source, DiagnosticListener<? super JavaFileObject> listener) {
        Class defClass = null;
        StringJavaSourceObject fileObject = new StringJavaSourceObject(className, source);
        final List<StringJavaSourceObject> fileObjects = List.of(fileObject);
        // コンパイルオプション
        List<String> options = new ArrayList<>();
        options.add("-verbose");

        // 参照するクラスのjarファイルを、コンパイルオプションに指定する。
        String classPath = getClassPath();
        if (classPath.length() > 0) {
            options.add("-classpath");
            options.add(classPath);
        }
        // コンパイルタスクを取得する。
        CompilationTask task = this.compiler.getTask(null, this.fileManager, listener, options, null, fileObjects);

        // コンパイルを実行する。
        if (!task.call()) {
            throw new RuntimeException("compile failed.");
        }
        try {
            defClass = (Class) getDefineClass(className);
        } catch (ClassNotFoundException ex) {
            throw new RuntimeException(ex);
        }
        return defClass;
    }

    private final List<String> extensionLocation = new ArrayList<>();

    public List<String> getExtensionClassLoactions() {
        return this.extensionLocation;
    }

    public void setExtensionClassLoactions(List<String> paths) {
        this.extensionLocation.clear();
        this.extensionLocation.addAll(paths);
    }

    /**
     * クラスパスの取得
     *
     * @param source
     * @return
     */
    private List<String> getClassLoactions(String source) {
        return List.of(System.getProperty("java.class.path").split(PATH_SEPARATOR));
    }

}
