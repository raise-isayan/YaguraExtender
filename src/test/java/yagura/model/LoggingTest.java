package yagura.model;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 *
 * @author isayan
 */
public class LoggingTest {

    public LoggingTest() {
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

    @Test
    public void testGetLogFileCounter() {
        System.out.println("testGetLogFileCounter");
        assertEquals(-1, Logging.getLogFileCounter("test_20200101"));
        assertEquals(0, Logging.getLogFileCounter("burp_20201201"));
        assertEquals(1, Logging.getLogFileCounter("burp_20210110_1"));
        assertEquals(9, Logging.getLogFileCounter("burp_20210110_9"));
        assertEquals(10, Logging.getLogFileCounter("burp_20250900_10"));
    }

}
