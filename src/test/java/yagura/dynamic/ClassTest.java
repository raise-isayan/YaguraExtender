package yagura.dynamic;

import extension.burp.FilterProperty;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Locale;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.tools.Diagnostic;
import javax.tools.DiagnosticListener;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 *
 * @author isayan
 */
public class ClassTest {

    private final static Logger logger = Logger.getLogger(ClassTest.class.getName());

    public ClassTest() {
    }

    @BeforeAll
    public static void setUpClass() {
    }

    @AfterAll
    public static void tearDownClass() {
    }

    @BeforeEach
    public void setUp() {
    }

    @AfterEach
    public void tearDown() {
    }

    String PACKAGE_NAME = getClass().getPackage().getName();

    String CLASS_NAME = "DynamicCompileTest";

    String QUALIFIED_CLASS_NAME = PACKAGE_NAME + "." + CLASS_NAME;

    String SOURCE
            = "package " + PACKAGE_NAME + ";"
            + "public class " + CLASS_NAME + " {"
            + "public " + CLASS_NAME + "() {}; "
            + "private int value = 10; "
            + "public int getValue(){ return value;} "
            + "public void setValue(int value){this.value = value;} "
            + "}";

    String SOURCE_ERROR
            = "package " + PACKAGE_NAME + ";"
            + "public class " + CLASS_NAME + " {"
            + "public " + CLASS_NAME + "() {}; "
            + "private int value = 10; "
            + "public intx getValue(){ return value;} "
            + "public void setValue(int value){this.value = value;} "
            + "}";

    private final DiagnosticListener listener = new DiagnosticListener() {
        @Override
        public void report(Diagnostic diagnostic) {
            System.out.println("className:" + diagnostic.getClass().getName());
            System.out.println("LineNumber:" + diagnostic.getLineNumber());
            System.out.println("Kind:" + diagnostic.getKind());
            System.out.println("Source:" + diagnostic.getSource());
            System.out.println("Code:" + diagnostic.getCode());
            System.out.println("Pos:" + diagnostic.getStartPosition() + "," + diagnostic.getEndPosition());
            System.out.println("Message:" + diagnostic.getMessage(Locale.getDefault()));
        }
    };

    @Test
    public void testTemplete() {
        System.out.println("testTemplete");
        SimpleJavaCompilerEngine engine = new SimpleJavaCompilerEngine();
        {
            System.out.println("cp:" + engine.getClassPath());
            BambdaTemplete templete = BambdaTemplete.create("testHTTP", "return true;", FilterProperty.FilterCategory.HTTP);
            System.out.println("Source:\r\n" + templete.getContent());
            engine.compile(templete.getFunctionName(), templete.getContent(), listener);
        }
        {
            BambdaTemplete templete = BambdaTemplete.create("testWEBSOCET", "return true;", FilterProperty.FilterCategory.WEBSOCKET);
            System.out.println("Source:\r\n" + templete.getContent());
            engine.compile(templete.getFunctionName(), templete.getContent(), listener);
        }
        {
            BambdaTemplete templete = BambdaTemplete.create("testSITEMAP", "return true;", FilterProperty.FilterCategory.SITE_MAP);
            System.out.println("Source:\r\n" + templete.getContent());
            engine.compile(templete.getFunctionName(), templete.getContent(), listener);
        }
    }

    @Test
    public void testImport() {
        System.out.println("testImport");
        SimpleJavaCompilerEngine engine = new SimpleJavaCompilerEngine();
        {
            BambdaTemplete templete = BambdaTemplete.create("testHTTP", "return requestResponse.request().isInScope();", FilterProperty.FilterCategory.HTTP);
            System.out.println("Source:\r\n" + templete.getContent());
            engine.compile(templete.getFunctionName(), templete.getContent(), listener);
        }
        {
            BambdaTemplete templete = BambdaTemplete.create("testHTTP", "return StatusCodeClass.CLASS_2XX_SUCCESS.contains(200);", FilterProperty.FilterCategory.HTTP);
            System.out.println("Source:\r\n" + templete.getContent());
            engine.compile(templete.getFunctionName(), templete.getContent(), listener);
        }
    }

    @Test
    public void testClass() {
        try {
            System.out.println("testClass");
            SimpleJavaCompilerEngine engine = new SimpleJavaCompilerEngine();
            Class dyn = engine.compile(QUALIFIED_CLASS_NAME, SOURCE, listener);
            Constructor constructor = dyn.getConstructor();
            Object instance = constructor.newInstance();
            Method m = dyn.getMethod("getValue");
            Object result = m.invoke(instance);
            System.out.println("result:" + result);
        } catch (NoSuchMethodException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        } catch (SecurityException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        } catch (IllegalAccessException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        } catch (IllegalArgumentException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        } catch (InvocationTargetException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        } catch (InstantiationException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }


    @Test
    public void testClassError() {
        try {
            System.out.println("testClassError");
            SimpleJavaCompilerEngine engine = new SimpleJavaCompilerEngine();
            Class dyn = engine.compile(QUALIFIED_CLASS_NAME, SOURCE_ERROR, listener);
        } catch (RuntimeException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

}
