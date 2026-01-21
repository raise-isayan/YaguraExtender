package yagura.dynamic;

import extension.burp.FilterProperty;
import java.io.File;
import java.io.FileNotFoundException;
import java.util.Locale;
import javax.tools.Diagnostic;
import javax.tools.DiagnosticListener;
import javax.tools.JavaFileObject;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.fail;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 *
 * @author isayan
 */
public class BambdaTempleteTest {

    public BambdaTempleteTest() {
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

    private final DiagnosticListener<JavaFileObject> listener = new DiagnosticListener() {
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
        try {
            String bambda_path = BambdaFileTest.class.getResource("/resources/HTTPHistoryViewFilter-SL.bambda").getPath();
            BambdaFile bamba = new BambdaFile();
            bamba.parse(new File(bambda_path));
            BambdaTemplete templete = BambdaTemplete.create(bamba.getFunction(), bamba.getSourceContents(), FilterProperty.FilterCategory.HTTP);
            System.out.println("function:" + templete.getFunctionName());
            System.out.println("content:" + templete.getContent());
            SimpleJavaCompilerEngine engine = new SimpleJavaCompilerEngine();
            engine.compile(templete.getFunctionName(), templete.getContent(), listener);
            Class dynamic = engine.getClass();
        } catch (FileNotFoundException ex) {
            fail(ex.getMessage(), ex);
        }
    }


}
