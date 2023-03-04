package extension.helpers;

import java.io.UnsupportedEncodingException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;

/**
 *
 * @author isayan
 */
public class MatchUtilTest {

    private final static Logger logger = Logger.getLogger(MatchUtilTest.class.getName());

    public MatchUtilTest() {
    }

    @BeforeAll
    public static void setUpClass() throws Exception {
    }

    @AfterAll
    public static void tearDownClass() throws Exception {
    }

    @BeforeEach
    public void setUp() {
    }

    @AfterEach
    public void tearDown() {
    }

    @Test
    public void testIsUrlencoded() {
        assertEquals(false, MatchUtil.isUrlencoded("あああ"));
        assertEquals(true, MatchUtil.isUrlencoded("%82%a0%82%a2%82%a4%82%a6%82%a8"));
        assertEquals(true, MatchUtil.isUrlencoded("0abcAZz9%23%Ff"));
        assertEquals(false, MatchUtil.isUrlencoded("0abc AZz9"));
        assertEquals(true, MatchUtil.isUrlencoded("0abcAZz9%25"));
        assertEquals(false, MatchUtil.isUrlencoded("<0abcAZz9%25>"));
        assertEquals(true, MatchUtil.isUrlencoded("eyJjb3VudGVyIjozLCJsb25nIjoiNDQzODkxMDkyMTgzNjQ3NzkyMTIzODY2Mzg5MzY0NDk0MTg5ODYzMjczOTA1ODc1OTI2OTkwNDIzMzk1MDM0NzE0MDcwOTk0NjA2ODc3NDUyNjM2OTMyMjUyNzg4OTA1OTgxODU0ODI1MjczNDQxNDA4NzQ3MTM3MTcwODMyODU4OTk2ODU0MjQxMTQxNzIyMDk0NzA1MjIwNTQwMTk4Mzc5NzA3MDU3OTQ0NjQxNTEwMTk4NjQwNjUxMDQ1NjI3NjkwNTc1MDEwODkyMDE3NTIxNTI3MDQxMTg5MDY4MjU1MjkxNjk1NDgwMDQxNTE0NDg1MDc5NDk1Mzg2ODE5NTQ4MTA0ODk1MzU3Nzc0NDU3NTY2NzM0MzI0NTQ0NDI0NjU4NDcxNDgwMTE4Mzk1OTQ5NTQ2Mjk5NjU0NjY0MzE3MTA4MjU3MjA5NTU5NDgwOTczMjQ0MjA2Njg2ODY4ODU2MTUyNzg5NzE1MTU1MDE0MTM5NTYwNTA4MDQxNjcxODY1OTk3NDkyNjM3OTAzNjkxNDYwNjg2OTA5NzA3NzQ5NDU0MjgxNDI1NzEzNzc2NTU2MjA1MjczMjk3MjM2OTYwNjcxMzcxNTAwMDMyNjkxNDA4MDIwNjI4MjU3NzExMDUzODIxOTk1MjAyNjIzMzA1Mjc5MDIwMDQxMzg3ODUyMzA0MTg3ODQyNDI4ODMyMTA5NjU3MTY5NzEzMTU3NTIyMjg0NDUzNzQwNzgyNDg0NjUwMjA0MjM3MTUwODg0MTI1NzE4MzI5ODc5OTMwNjg0MjYxOTk3MjkzNzMzOTM1NTIwNDg3OTQ4ODg1NDUwOTE2ODYxNDczNDg0MTg2Nzc0NjMxNjIwMTgzMDk1MjQ0ODY1MjUwNjA3MDIxOTM5NzcyMzA0ODMyNzY1NTkzNDEyMTEzOTQ1MzU0MzY2MTA1OTY4NjM3OTQyOTA1NjM2MTI1NDg5NTc4OTczNzU5Mjg5OTg1MTg4NTY1NzMwOTIzMjg2NTU3OTk0ODU3MzM2ODAwNDk3Nzc4NDYzNzYyMzg3MTA4NDc2ODkzMDU4Mjc5MDMyODg2ODA5NDcyNjc4NDMzMTk1NjM5ODEwNzc1MzM0NDQwNDQ0OTgyMzk4NzU2MzYwNjQ3MDQ5NTA4NjUxMTM5MjA4NDQ1OTY4OTkxNjA5MzY2MDIyOTIwNjgxMTY3MjUxNjY5MjI5NjYzODA5NTkyNDgxNDUxNTEyNjU3NjMzOTM4MDgyNTk4OTIyNTczNDg3MDA4MjA0OTM5ODY1NjU4NjY4MjUwMjQ4MjE2MzYxNDY4NDY5NjEwOTc3OTgwMzMwMzA2OSJ9Cg%3d%3d"));
        assertEquals(true, MatchUtil.isUrlencoded("JTAxJTAyJTAzJTA0JTA1JTA2JTA3JTA4JTA5JTBhJTBiJTBjJTBkJTBlJTBmJTEwJTExJTEyJTEzJTE0JTE1JTE2JTE3JTE4JTE5JTFhJTFiJTFjJTFkJTFlJTFmJTIwJTIxJTIyJTIzJTI0JTI1JTI2JTI3JTI4JTI5JTJhJTJiJTJjJTJkJTJlJTJmJTMwJTMxJTMyJTMzJTM0JTM1JTM2JTM3JTM4JTM5JTNhJTNiJTNjJTNkJTNlJTNmJTQwJTQxJTQyJTQzJTQ0JTQ1JTQ2JTQ3JTQ4JTQ5JTRhJTRiJTRjJTRkJTRlJTRmJTUwJTUxJTUyJTUzJTU0JTU1JTU2JTU3JTU4JTU5JTVhJTViJTVjJTVkJTVlJTVmJTYwJTYxJTYyJTYzJTY0JTY1JTY2JTY3JTY4JTY5JTZhJTZiJTZjJTZkJTZlJTZmJTcwJTcxJTcyJTczJTc0JTc1JTc2JTc3JTc4JTc5JTdhJTdiJTdjJTdkJTdlJTdmJTgwJTgxJTgyJTgzJTg0JTg1JTg2JTg3JTg4JTg5JThhJThiJThjJThkJThlJThmJTkwJTkxJTkyJTkzJTk0JTk1JTk2JTk3JTk4JTk5JTlhJTliJTljJTlkJTllJTlmJWEwJWExJWEyJWEzJWE0JWE1JWE2JWE3JWE4JWE5JWFhJWFiJWFjJWFkJWFlJWFmJWIwJWIxJWIyJWIzJWI0JWI1JWI2JWI3JWI4JWI5JWJhJWJiJWJjJWJkJWJlJWJmJWMwJWMxJWMyJWMzJWM0JWM1JWM2JWM3JWM4JWM5JWNhJWNiJWNjJWNkJWNlJWNmJWQwJWQxJWQyJWQzJWQ0JWQ1JWQ2JWQ3JWQ4JWQ5JWRhJWRiJWRjJWRkJWRlJWRmJWUwJWUxJWUyJWUzJWU0JWU1JWU2JWU3JWU4JWU5JWVhJWViJWVjJWVkJWVlJWVmJWYwJWYxJWYyJWYzJWY0JWY1JWY2JWY3JWY4JWY5JWZhJWZiJWZjJWZkJWZlJWZmJTAxJTAyJTAzJTA0JTA1JTA2JTA3JTA4JTA5JTBhJTBiJTBjJTBkJTBlJTBmJTEwJTExJTEyJTEzJTE0JTE1JTE2JTE3JTE4JTE5JTFhJTFiJTFjJTFkJTFlJTFmJTIwJTIxJTIyJTIzJTI0JTI1JTI2JTI3JTI4JTI5JTJhJTJiJTJjJTJkJTJlJTJmJTMwJTMxJTMyJTMzJTM0JTM1JTM2JTM3JTM4JTM5JTNhJTNiJTNjJTNkJTNlJTNmJTQwJTQxJTQyJTQzJTQ0JTQ1JTQ2JTQ3JTQ4JTQ5JTRhJTRiJTRjJTRkJTRlJTRmJTUwJTUxJTUyJTUzJTU0JTU1JTU2JTU3JTU4JTU5JTVhJTViJTVjJTVkJTVlJTVmJTYwJTYxJTYyJTYzJTY0JTY1JTY2JTY3JTY4JTY5JTZhJTZiJTZjJTZkJTZlJTZmJTcwJTcxJTcyJTczJTc0JTc1JTc2JTc3JTc4JTc5JTdhJTdiJTdjJTdkJTdlJTdmJTgwJTgxJTgyJTgzJTg0JTg1JTg2JTg3JTg4JTg5JThhJThiJThjJThkJThlJThmJTkwJTkxJTkyJTkzJTk0JTk1JTk2JTk3JTk4JTk5JTlhJTliJTljJTlkJTllJTlmJWEwJWExJWEyJWEzJWE0JWE1JWE2JWE3JWE4JWE5JWFhJWFiJWFjJWFkJWFlJWFmJWIwJWIxJWIyJWIzJWI0JWI1JWI2JWI3JWI4JWI5JWJhJWJiJWJjJWJkJWJlJWJmJWMwJWMxJWMyJWMzJWM0JWM1JWM2JWM3JWM4JWM5JWNhJWNiJWNjJWNkJWNlJWNmJWQwJWQxJWQyJWQzJWQ0JWQ1JWQ2JWQ3JWQ4JWQ5JWRhJWRiJWRjJWRkJWRlJWRmJWUwJWUxJWUyJWUzJWU0JWU1JWU2JWU3JWU4JWU5JWVhJWViJWVjJWVkJWVlJWVmJWYwJWYxJWYyJWYzJWY0JWY1JWY2JWY3JWY4JWY5JWZhJWZiJWZjJWZkJWZlJWZmJTAxJTAyJTAzJTA0JTA1JTA2JTA3JTA4JTA5JTBhJTBiJTBjJTBkJTBlJTBmJTEwJTExJTEyJTEzJTE0JTE1JTE2JTE3JTE4JTE5JTFhJTFiJTFjJTFkJTFlJTFmJTIwJTIxJTIyJTIzJTI0JTI1JTI2JTI3JTI4JTI5JTJhJTJiJTJjJTJkJTJlJTJmJTMwJTMxJTMyJTMzJTM0JTM1JTM2JTM3JTM4JTM5JTNhJTNiJTNjJTNkJTNlJTNmJTQwJTQxJTQyJTQzJTQ0JTQ1JTQ2JTQ3JTQ4JTQ5JTRhJTRiJTRjJTRkJTRlJTRmJTUwJTUxJTUyJTUzJTU0JTU1JTU2JTU3JTU4JTU5JTVhJTViJTVjJTVkJTVlJTVmJTYwJTYxJTYyJTYzJTY0JTY1JTY2JTY3JTY4JTY5JTZhJTZiJTZjJTZkJTZlJTZmJTcwJTcxJTcyJTczJTc0JTc1JTc2JTc3JTc4JTc5JTdhJTdiJTdjJTdkJTdlJTdmJTgwJTgxJTgyJTgzJTg0JTg1JTg2JTg3JTg4JTg5JThhJThiJThjJThkJThlJThmJTkwJTkxJTkyJTkzJTk0JTk1JTk2JTk3JTk4JTk5JTlhJTliJTljJTlkJTllJTlmJWEwJWExJWEyJWEzJWE0JWE1JWE2JWE3JWE4JWE5JWFhJWFiJWFjJWFkJWFlJWFmJWIwJWIxJWIyJWIzJWI0JWI1JWI2JWI3JWI4JWI5JWJhJWJiJWJjJWJkJWJlJWJmJWMwJWMxJWMyJWMzJWM0JWM1JWM2JWM3JWM4JWM5JWNhJWNiJWNjJWNkJWNlJWNmJWQwJWQxJWQyJWQzJWQ0JWQ1JWQ2JWQ3JWQ4JWQ5JWRhJWRiJWRjJWRkJWRlJWRmJWUwJWUxJWUyJWUzJWU0JWU1JWU2JWU3JWU4JWU5JWVhJWViJWVjJWVkJWVlJWVmJWYwJWYxJWYyJWYzJWY0JWY1JWY2JWY3JWY4JWY5JWZhJWZiJWZjJWZkJWZlJWZmJTAxJTAyJTAzJTA0JTA1JTA2JTA3JTA4JTA5JTBhJTBiJTBjJTBkJTBlJTBmJTEwJTExJTEyJTEzJTE0JTE1JTE2JTE3JTE4JTE5JTFhJTFiJTFjJTFkJTFlJTFmJTIwJTIxJTIyJTIzJTI0JTI1JTI2JTI3JTI4JTI5JTJhJTJiJTJjJTJkJTJlJTJmJTMwJTMxJTMyJTMzJTM0JTM1JTM2JTM3JTM4JTM5JTNhJTNiJTNjJTNkJTNlJTNmJTQwJTQxJTQyJTQzJTQ0JTQ1JTQ2JTQ3JTQ4JTQ5JTRhJTRiJTRjJTRkJTRlJTRmJTUwJTUxJTUyJTUzJTU0JTU1JTU2JTU3JTU4JTU5JTVhJTViJTVjJTVkJTVlJTVmJTYwJTYxJTYyJTYzJTY0JTY1JTY2JTY3JTY4JTY5JTZhJTZiJTZjJTZkJTZlJTZmJTcwJTcxJTcyJTczJTc0JTc1JTc2JTc3JTc4JTc5JTdhJTdiJTdjJTdkJTdlJTdmJTgwJTgxJTgyJTgzJTg0JTg1JTg2JTg3JTg4JTg5JThhJThiJThjJThkJThlJThmJTkwJTkxJTkyJTkzJTk0JTk1JTk2JTk3JTk4JTk5JTlhJTliJTljJTlkJTllJTlmJWEwJWExJWEyJWEzJWE0JWE1JWE2JWE3JWE4JWE5JWFhJWFiJWFjJWFkJWFlJWFmJWIwJWIxJWIyJWIzJWI0JWI1JWI2JWI3JWI4JWI5JWJhJWJiJWJjJWJkJWJlJWJmJWMwJWMxJWMyJWMzJWM0JWM1JWM2JWM3JWM4JWM5JWNhJWNiJWNjJWNkJWNlJWNmJWQwJWQxJWQyJWQzJWQ0JWQ1JWQ2JWQ3JWQ4JWQ5JWRhJWRiJWRjJWRkJWRlJWRmJWUwJWUxJWUyJWUzJWU0JWU1JWU2JWU3JWU4JWU5JWVhJWViJWVjJWVkJWVlJWVmJWYwJWYxJWYyJWYzJWY0JWY1JWY2JWY3JWY4JWY5JWZhJWZiJWZjJWZkJWZlJWZmJTAxJTAyJTAzJTA0JTA1JTA2JTA3JTA4JTA5JTBhJTBiJTBjJTBkJTBlJTBmJTEwJTExJTEyJTEzJTE0JTE1JTE2JTE3JTE4JTE5JTFhJTFiJTFjJTFkJTFlJTFmJTIwJTIxJTIyJTIzJTI0JTI1JTI2JTI3JTI4JTI5JTJhJTJiJTJjJTJkJTJlJTJmJTMwJTMxJTMyJTMzJTM0JTM1JTM2JTM3JTM4JTM5JTNhJTNiJTNjJTNkJTNlJTNmJTQwJTQxJTQyJTQzJTQ0JTQ1JTQ2JTQ3JTQ4JTQ5JTRhJTRiJTRjJTRkJTRlJTRmJTUwJTUxJTUyJTUzJTU0JTU1JTU2JTU3JTU4JTU5JTVhJTViJTVjJTVkJTVlJTVmJTYwJTYxJTYyJTYzJTY0JTY1JTY2JTY3JTY4JTY5JTZhJTZiJTZjJTZkJTZlJTZmJTcwJTcxJTcyJTczJTc0JTc1JTc2JTc3JTc4JTc5JTdhJTdiJTdjJTdkJTdlJTdmJTgwJTgxJTgyJTgzJTg0JTg1JTg2JTg3JTg4JTg5JThhJThiJThjJThkJThlJThmJTkwJTkxJTkyJTkzJTk0JTk1JTk2JTk3JTk4JTk5JTlhJTliJTljJTlkJTllJTlmJWEwJWExJWEyJWEzJWE0JWE1JWE2JWE3JWE4JWE5JWFhJWFiJWFjJWFkJWFlJWFmJWIwJWIxJWIyJWIzJWI0JWI1JWI2JWI3JWI4JWI5JWJhJWJiJWJjJWJkJWJlJWJmJWMwJWMxJWMyJWMzJWM0JWM1JWM2JWM3JWM4JWM5JWNhJWNiJWNjJWNkJWNlJWNmJWQwJWQxJWQyJWQzJWQ0JWQ1JWQ2JWQ3JWQ4JWQ5JWRhJWRiJWRjJWRkJWRlJWRmJWUwJWUxJWUyJWUzJWU0JWU1JWU2JWU3JWU4JWU5JWVhJWViJWVjJWVkJWVlJWVmJWYwJWYxJWYyJWYzJWY0JWY1JWY2JWY3JWY4JWY5JWZhJWZiJWZjJWZkJWZlJWZmJTAxJTAyJTAzJTA0JTA1JTA2JTA3JTA4JTA5JTBhJTBiJTBjJTBkJTBlJTBmJTEwJTExJTEyJTEzJTE0JTE1JTE2JTE3JTE4JTE5JTFhJTFiJTFjJTFkJTFlJTFmJTIwJTIxJTIyJTIzJTI0JTI1JTI2JTI3JTI4JTI5JTJhJTJiJTJjJTJkJTJlJTJmJTMwJTMxJTMyJTMzJTM0JTM1JTM2JTM3JTM4JTM5JTNhJTNiJTNjJTNkJTNlJTNmJTQwJTQxJTQyJTQzJTQ0JTQ1JTQ2JTQ3JTQ4JTQ5JTRhJTRiJTRjJTRkJTRlJTRmJTUwJTUxJTUyJTUzJTU0JTU1JTU2JTU3JTU4JTU5JTVhJTViJTVjJTVkJTVlJTVmJTYwJTYxJTYyJTYzJTY0JTY1JTY2JTY3JTY4JTY5JTZhJTZiJTZjJTZkJTZlJTZmJTcwJTcxJTcyJTczJTc0JTc1JTc2JTc3JTc4JTc5JTdhJTdiJTdjJTdkJTdlJTdmJTgwJTgxJTgyJTgzJTg0JTg1JTg2JTg3JTg4JTg5JThhJThiJThjJThkJThlJThmJTkwJTkxJTkyJTkzJTk0JTk1JTk2JTk3JTk4JTk5JTlhJTliJTljJTlkJTllJTlmJWEwJWExJWEyJWEzJWE0JWE1JWE2JWE3JWE4JWE5JWFhJWFiJWFjJWFkJWFlJWFmJWIwJWIxJWIyJWIzJWI0JWI1JWI2JWI3JWI4JWI5JWJhJWJiJWJjJWJkJWJlJWJmJWMwJWMxJWMyJWMzJWM0JWM1JWM2JWM3JWM4JWM5JWNhJWNiJWNjJWNkJWNlJWNmJWQwJWQxJWQyJWQzJWQ0JWQ1JWQ2JWQ3JWQ4JWQ5JWRhJWRiJWRjJWRkJWRlJWRmJWUwJWUxJWUyJWUzJWU0JWU1JWU2JWU3JWU4JWU5JWVhJWViJWVjJWVkJWVlJWVmJWYwJWYxJWYyJWYzJWY0JWY1JWY2JWY3JWY4JWY5JWZhJWZiJWZjJWZkJWZlJWZmJTAxJTAyJTAzJTA0JTA1JTA2JTA3JTA4JTA5JTBhJTBiJTBjJTBkJTBlJTBmJTEwJTExJTEyJTEzJTE0JTE1JTE2JTE3JTE4JTE5JTFhJTFiJTFjJTFkJTFlJTFmJTIwJTIxJTIyJTIzJTI0JTI1JTI2JTI3JTI4JTI5JTJhJTJiJTJjJTJkJTJlJTJmJTMwJTMxJTMyJTMzJTM0JTM1JTM2JTM3JTM4JTM5JTNhJTNiJTNjJTNkJTNlJTNmJTQwJTQxJTQyJTQzJTQ0JTQ1JTQ2JTQ3JTQ4JTQ5JTRhJTRiJTRjJTRkJTRlJTRmJTUwJTUxJTUyJTUzJTU0JTU1JTU2JTU3JTU4JTU5JTVhJTViJTVjJTVkJTVlJTVmJTYwJTYxJTYyJTYzJTY0JTY1JTY2JTY3JTY4JTY5JTZhJTZiJTZjJTZkJTZlJTZmJTcwJTcxJTcyJTczJTc0JTc1JTc2JTc3JTc4JTc5JTdhJTdiJTdjJTdkJTdlJTdmJTgwJTgxJTgyJTgzJTg0JTg1JTg2JTg3JTg4JTg5JThhJThiJThjJThkJThlJThmJTkwJTkxJTkyJTkzJTk0JTk1JTk2JTk3JTk4JTk5JTlhJTliJTljJTlkJTllJTlmJWEwJWExJWEyJWEzJWE0JWE1JWE2JWE3JWE4JWE5JWFhJWFiJWFjJWFkJWFlJWFmJWIwJWIxJWIyJWIzJWI0JWI1JWI2JWI3JWI4JWI5JWJhJWJiJWJjJWJkJWJlJWJmJWMwJWMxJWMyJWMzJWM0JWM1JWM2JWM3JWM4JWM5JWNhJWNiJWNjJWNkJWNlJWNmJWQwJWQxJWQyJWQzJWQ0JWQ1JWQ2JWQ3JWQ4JWQ5JWRhJWRiJWRjJWRkJWRlJWRmJWUwJWUxJWUyJWUzJWU0JWU1JWU2JWU3JWU4JWU5JWVhJWViJWVjJWVkJWVlJWVmJWYwJWYxJWYyJWYzJWY0JWY1JWY2JWY3JWY4JWY5JWZhJWZiJWZjJWZkJWZlJWZmJTAxJTAyJTAzJTA0JTA1JTA2JTA3JTA4JTA5JTBhJTBiJTBjJTBkJTBlJTBmJTEwJTExJTEyJTEzJTE0JTE1JTE2JTE3JTE4JTE5JTFhJTFiJTFjJTFkJTFlJTFmJTIwJTIxJTIyJTIzJTI0JTI1JTI2JTI3JTI4JTI5JTJhJTJiJTJjJTJkJTJlJTJmJTMwJTMxJTMyJTMzJTM0JTM1JTM2JTM3JTM4JTM5JTNhJTNiJTNjJTNkJTNlJTNmJTQwJTQxJTQyJTQzJTQ0JTQ1JTQ2JTQ3JTQ4JTQ5JTRhJTRiJTRjJTRkJTRlJTRmJTUwJTUxJTUyJTUzJTU0JTU1JTU2JTU3JTU4JTU5JTVhJTViJTVjJTVkJTVlJTVmJTYwJTYxJTYyJTYzJTY0JTY1JTY2JTY3JTY4JTY5JTZhJTZiJTZjJTZkJTZlJTZmJTcwJTcxJTcyJTczJTc0JTc1JTc2JTc3JTc4JTc5JTdhJTdiJTdjJTdkJTdlJTdmJTgwJTgxJTgyJTgzJTg0JTg1JTg2JTg3JTg4JTg5JThhJThiJThjJThkJThlJThmJTkwJTkxJTkyJTkzJTk0JTk1JTk2JTk3JTk4JTk5JTlhJTliJTljJTlkJTllJTlmJWEwJWExJWEyJWEzJWE0JWE1JWE2JWE3JWE4JWE5JWFhJWFiJWFjJWFkJWFlJWFmJWIwJWIxJWIyJWIzJWI0JWI1JWI2JWI3JWI4JWI5JWJhJWJiJWJjJWJkJWJlJWJmJWMwJWMxJWMyJWMzJWM0JWM1JWM2JWM3JWM4JWM5JWNhJWNiJWNjJWNkJWNlJWNmJWQwJWQxJWQyJWQzJWQ0JWQ1JWQ2JWQ3JWQ4JWQ5JWRhJWRiJWRjJWRkJWRlJWRmJWUwJWUxJWUyJWUzJWU0JWU1JWU2JWU3JWU4JWU5JWVhJWViJWVjJWVkJWVlJWVmJWYwJWYxJWYyJWYzJWY0JWY1JWY2JWY3JWY4JWY5JWZhJWZiJWZjJWZkJWZlJWZmJTAxJTAyJTAzJTA0JTA1JTA2JTA3JTA4JTA5JTBhJTBiJTBjJTBkJTBlJTBmJTEwJTExJTEyJTEzJTE0JTE1JTE2JTE3JTE4JTE5JTFhJTFiJTFjJTFkJTFlJTFmJTIwJTIxJTIyJTIzJTI0JTI1JTI2JTI3JTI4JTI5JTJhJTJiJTJjJTJkJTJlJTJmJTMwJTMxJTMyJTMzJTM0JTM1JTM2JTM3JTM4JTM5JTNhJTNiJTNjJTNkJTNlJTNmJTQwJTQxJTQyJTQzJTQ0JTQ1JTQ2JTQ3JTQ4JTQ5JTRhJTRiJTRjJTRkJTRlJTRmJTUwJTUxJTUyJTUzJTU0JTU1JTU2JTU3JTU4JTU5JTVhJTViJTVjJTVkJTVlJTVmJTYwJTYxJTYyJTYzJTY0JTY1JTY2JTY3JTY4JTY5JTZhJTZiJTZjJTZkJTZlJTZmJTcwJTcxJTcyJTczJTc0JTc1JTc2JTc3JTc4JTc5JTdhJTdiJTdjJTdkJTdlJTdmJTgwJTgxJTgyJTgzJTg0JTg1JTg2JTg3JTg4JTg5JThhJThiJThjJThkJThlJThmJTkwJTkxJTkyJTkzJTk0JTk1JTk2JTk3JTk4JTk5JTlhJTliJTljJTlkJTllJTlmJWEwJWExJWEyJWEzJWE0JWE1JWE2JWE3JWE4JWE5JWFhJWFiJWFjJWFkJWFlJWFmJWIwJWIxJWIyJWIzJWI0JWI1JWI2JWI3JWI4JWI5JWJhJWJiJWJjJWJkJWJlJWJmJWMwJWMxJWMyJWMzJWM0JWM1JWM2JWM3JWM4JWM5JWNhJWNiJWNjJWNkJWNlJWNmJWQwJWQxJWQyJWQzJWQ0JWQ1JWQ2JWQ3JWQ4JWQ5JWRhJWRiJWRjJWRkJWRlJWRmJWUwJWUxJWUyJWUzJWU0JWU1JWU2JWU3JWU4JWU5JWVhJWViJWVjJWVkJWVlJWVmJWYwJWYxJWYyJWYzJWY0JWY1JWY2JWY3JWY4JWY5JWZhJWZiJWZjJWZkJWZlJWZmJTAxJTAyJTAzJTA0JTA1JTA2JTA3JTA4JTA5JTBhJTBiJTBjJTBkJTBlJTBmJTEwJTExJTEyJTEzJTE0JTE1JTE2JTE3JTE4JTE5JTFhJTFiJTFjJTFkJTFlJTFmJTIwJTIxJTIyJTIzJTI0JTI1JTI2JTI3JTI4JTI5JTJhJTJiJTJjJTJkJTJlJTJmJTMwJTMxJTMyJTMzJTM0JTM1JTM2JTM3JTM4JTM5JTNhJTNiJTNjJTNkJTNlJTNmJTQwJTQxJTQyJTQzJTQ0JTQ1JTQ2JTQ3JTQ4JTQ5JTRhJTRiJTRjJTRkJTRlJTRmJTUwJTUxJTUyJTUzJTU0JTU1JTU2JTU3JTU4JTU5JTVhJTViJTVjJTVkJTVlJTVmJTYwJTYxJTYyJTYzJTY0JTY1JTY2JTY3JTY4JTY5JTZhJTZiJTZjJTZkJTZlJTZmJTcwJTcxJTcyJTczJTc0JTc1JTc2JTc3JTc4JTc5JTdhJTdiJTdjJTdkJTdlJTdmJTgwJTgxJTgyJTgzJTg0JTg1JTg2JTg3JTg4JTg5JThhJThiJThjJThkJThlJThmJTkwJTkxJTkyJTkzJTk0JTk1JTk2JTk3JTk4JTk5JTlhJTliJTljJTlkJTllJTlmJWEwJWExJWEyJWEzJWE0JWE1JWE2JWE3JWE4JWE5JWFhJWFiJWFjJWFkJWFlJWFmJWIwJWIxJWIyJWIzJWI0JWI1JWI2JWI3JWI4JWI5JWJhJWJiJWJjJWJkJWJlJWJmJWMwJWMxJWMyJWMzJWM0JWM1JWM2JWM3JWM4JWM5JWNhJWNiJWNjJWNkJWNlJWNmJWQwJWQxJWQyJWQzJWQ0JWQ1JWQ2JWQ3JWQ4JWQ5JWRhJWRiJWRjJWRkJWRlJWRmJWUwJWUxJWUyJWUzJWU0JWU1JWU2JWU3JWU4JWU5JWVhJWViJWVjJWVkJWVlJWVmJWYwJWYxJWYyJWYzJWY0JWY1JWY2JWY3JWY4JWY5JWZhJWZiJWZjJWZkJWZlJWZmJTAxJTAyJTAzJTA0JTA1JTA2JTA3JTA4JTA5JTBhJTBiJTBjJTBkJTBlJTBmJTEwJTExJTEyJTEzJTE0JTE1JTE2JTE3JTE4JTE5JTFhJTFiJTFjJTFkJTFlJTFmJTIwJTIxJTIyJTIzJTI0JTI1JTI2JTI3JTI4JTI5JTJhJTJiJTJjJTJkJTJlJTJmJTMwJTMxJTMyJTMzJTM0JTM1JTM2JTM3JTM4JTM5JTNhJTNiJTNjJTNkJTNlJTNmJTQwJTQxJTQyJTQzJTQ0JTQ1JTQ2JTQ3JTQ4JTQ5JTRhJTRiJTRjJTRkJTRlJTRmJTUwJTUxJTUyJTUzJTU0JTU1JTU2JTU3JTU4JTU5JTVhJTViJTVjJTVkJTVlJTVmJTYwJTYxJTYyJTYzJTY0JTY1JTY2JTY3JTY4JTY5JTZhJTZiJTZjJTZkJTZlJTZmJTcwJTcxJTcyJTczJTc0JTc1JTc2JTc3JTc4JTc5JTdhJTdiJTdjJTdkJTdlJTdmJTgwJTgxJTgyJTgzJTg0JTg1JTg2JTg3JTg4JTg5JThhJThiJThjJThkJThlJThmJTkwJTkxJTkyJTkzJTk0JTk1JTk2JTk3JTk4JTk5JTlhJTliJTljJTlkJTllJTlmJWEwJWExJWEyJWEzJWE0JWE1JWE2JWE3JWE4JWE5JWFhJWFiJWFjJWFkJWFlJWFmJWIwJWIxJWIyJWIzJWI0JWI1JWI2JWI3JWI4JWI5JWJhJWJiJWJjJWJkJWJlJWJmJWMwJWMxJWMyJWMzJWM0JWM1JWM2JWM3JWM4JWM5JWNhJWNiJWNjJWNkJWNlJWNmJWQwJWQxJWQyJWQzJWQ0JWQ1JWQ2JWQ3JWQ4JWQ5JWRhJWRiJWRjJWRkJWRlJWRmJWUwJWUxJWUyJWUzJWU0JWU1JWU2JWU3JWU4JWU5JWVhJWViJWVjJWVkJWVlJWVmJWYwJWYxJWYyJWYzJWY0JWY1JWY2JWY3JWY4JWY5JWZhJWZiJWZjJWZkJWZlJWZmCg%3d%3d"));
    }

    /**
     * Test of ToSmartMatch method, of class TransUtil.
     */
    @Test
    public void testToSmartMatch() {
        System.out.println("ToSmartMatch");
        {
            String regex = MatchUtil.toSmartMatch("!\"#$%&'()=-^~\\|@{}:*;+?_<>,./");
            Pattern p = Pattern.compile(regex);
            assertTrue(p.matcher("!\"#$%&'()=-^~\\|@{}:*;+?_<>,./").matches());
        }
        {
            String regex = MatchUtil.toSmartMatch("!\"#$%&'()=-^~\\|@{}:*;+?_<>,./");
            Pattern p = Pattern.compile(regex);
            assertTrue(p.matcher("%21%22%23%24%25%26%27%28%29%3d%2d%5e%7e%5c%7c%40%7b%7d%3a%2a%3b%2b%3f%5f%3c%3e%2c%2e%2f").matches());
        }
        {
            String regex = MatchUtil.toSmartMatch("!\"#$%&'()=-^~\\|@{}:*;+?_<>,./");
            Pattern p = Pattern.compile(regex);
            assertTrue(p.matcher("%u0021%u0022%u0023%u0024%u0025%u0026%u0027%u0028%u0029%u003d%u002d%u005e%u007e%u005c%u007c%u0040%u007b%u007d%u003a%u002a%u003b%u002b%u003f%u005f%u003c%u003e%u002c%u002e%u002f").matches());
        }
        {
            String regex = MatchUtil.toSmartMatch("!\"#$%&'()=-^~\\|@{}:*;+?_<>,./");
            Pattern p = Pattern.compile(regex);
            assertTrue(p.matcher("!&quot;#$%&amp;&#39;()=-^~\\|@{}:*;+?_&lt;&gt;,./").matches());
        }
        {
            String regex = MatchUtil.toSmartMatch("!\"#$%&'()=-^~\\|@{}:*;+?_<>,./");
            Pattern p = Pattern.compile(regex);
            assertTrue(p.matcher("\\u0021\\u0022\\u0023\\u0024\\u0025\\u0026\\u0027\\u0028\\u0029\\u003d\\u002d\\u005e\\u007e\\u005c\\u007c\\u0040\\u007b\\u007d\\u003a\\u002a\\u003b\\u002b\\u003f\\u005f\\u003c\\u003e\\u002c\\u002e\\u002f").matches());
        }
        {
            String regex = MatchUtil.toSmartMatch("!\"#$%&'()=-^~\\|@{}:*;+?_<>,./");
            Pattern p = Pattern.compile(regex);
            assertTrue(p.matcher("\\x21\\x22\\x23\\x24\\x25\\x26\\x27\\x28\\x29\\x3d\\x2d\\x5e\\x7e\\x5c\\x7c\\x40\\x7b\\x7d\\x3a\\x2a\\x3b\\x2b\\x3f\\x5f\\x3c\\x3e\\x2c\\x2e\\x2f").matches());
        }
        {
            String regex = MatchUtil.toSmartMatch("<script>alert(/0/)</script>!\"#$%&'()=-^~\\|@{}:*;+?_<>,./");
            Pattern p = Pattern.compile(regex);
            assertTrue(p.matcher("<script>alert(/0/)</script>!\"#$%&'()=-^~\\|@{}:*;+?_<>,./").matches());
        }
        {
            String regex = MatchUtil.toSmartMatch("<script>alert(/0/)</script>!\"#$%&'()=-^~\\|@{}:*;+?_<>,./");
            Pattern p = Pattern.compile(regex);
            assertTrue(p.matcher("%3c%73%63%72%69%70%74%3e%61%6c%65%72%74%28%2f%30%2f%29%3c%2f%73%63%72%69%70%74%3e!\"#$%&'()=-^~\\|@{}:*;+?_<>,./").matches());
        }
        {
            String regex = MatchUtil.toSmartMatch("<script>alert(/0/)</script>!\"#$%&'()=-^~\\|@{}:*;+?_<>,./");
            Pattern p = Pattern.compile(regex);
            assertTrue(p.matcher("%3c%73%63%72%69%70%74%3e%61%6c%65%72%74%28%2f%30%2f%29%3c%2f%73%63%72%69%70%74%3e\\x21\\x22\\x23\\x24\\x25\\x26\\x27\\x28\\x29\\x3d\\x2d\\x5e\\x7e\\x5c\\x7c\\x40\\x7b\\x7d\\x3a\\x2a\\x3b\\x2b\\x3f\\x5f\\x3c\\x3e\\x2c\\x2e\\x2f").matches());
        }
        /* wild card */
        {
            String regex = MatchUtil.toSmartMatch("a?a");
            Pattern p = Pattern.compile(regex);
            assertTrue(p.matcher("aXa").matches());
        }
        {
            String regex = MatchUtil.toSmartMatch("a?a??b???c");
            Pattern p = Pattern.compile(regex);
            assertTrue(p.matcher("aXaYYbZZZc").matches());
        }
        {
            String regex = MatchUtil.toSmartMatch("a?a??bc?");
            Pattern p = Pattern.compile(regex);
            assertTrue(p.matcher("aXaYYbcZ").matches());
        }
        {
            String regex = MatchUtil.toSmartMatch("*aa");
            Pattern p = Pattern.compile(regex);
            assertTrue(p.matcher("XYZaa").matches());
        }
        {
            String regex = MatchUtil.toSmartMatch("a*a");
            Pattern p = Pattern.compile(regex);
            assertTrue(p.matcher("aa").matches());
            assertTrue(p.matcher("aXa").matches());
            assertTrue(p.matcher("aXYa").matches());
            assertTrue(p.matcher("aXYZa").matches());
        }
        {
            String regex = MatchUtil.toSmartMatch("aa*");
            Pattern p = Pattern.compile(regex);
            assertTrue(p.matcher("aaXYZ").matches());
        }
        /* wild card escape */
        {
            String regex = MatchUtil.toSmartMatch("a\\?a");
            Pattern p = Pattern.compile(regex);
            assertTrue(p.matcher("a?a").matches());
        }
        {
            String regex = MatchUtil.toSmartMatch("a\\?a\\??b?\\??c");
            Pattern p = Pattern.compile(regex);
            assertTrue(p.matcher("a?a?YbZ?Zc").matches());
        }
        {
            String regex = MatchUtil.toSmartMatch("a?a\\");
            Pattern p = Pattern.compile(regex);
            assertTrue(p.matcher("aZa\\").matches());
        }
        {
            String regex = MatchUtil.toSmartMatch("a\\*a");
            Pattern p = Pattern.compile(regex);
            assertTrue(p.matcher("a*a").matches());
        }
        {
            String regex = MatchUtil.toSmartMatch("a*a\\");
            Pattern p = Pattern.compile(regex);
            assertTrue(p.matcher("aXa\\").matches());
        }

    }

    /**
     * Test of ToSmartMatch_charset method, of class TransUtil.
     */
    @Test
    public void testToSmartMatch_charset() {
        System.out.println("ToSmartMatch_charset");
        try {
            {
                String regex = MatchUtil.toSmartMatch("!\"#$%&'()=-^~\\|@{}:*;+?_<>,./", "UTF-8");
                Pattern p = Pattern.compile(regex);
                assertTrue(p.matcher("!\"#$%&'()=-^~\\|@{}:*;+?_<>,./").matches());
            }
            {
                String regex = MatchUtil.toSmartMatch("!\"#$%&'()=-^~\\|@{}:*;+?_<>,./", "UTF-8");
                Pattern p = Pattern.compile(regex);
                assertTrue(p.matcher("%21%22%23%24%25%26%27%28%29%3d%2d%5e%7e%5c%7c%40%7b%7d%3a%2a%3b%2b%3f%5f%3c%3e%2c%2e%2f").matches());
            }
            {
                String regex = MatchUtil.toSmartMatch("!\"#$%&'()=-^~\\|@{}:*;+?_<>,./", "UTF-8");
                Pattern p = Pattern.compile(regex);
                assertTrue(p.matcher("%u0021%u0022%u0023%u0024%u0025%u0026%u0027%u0028%u0029%u003d%u002d%u005e%u007e%u005c%u007c%u0040%u007b%u007d%u003a%u002a%u003b%u002b%u003f%u005f%u003c%u003e%u002c%u002e%u002f").matches());
            }
            {
                String regex = MatchUtil.toSmartMatch("!\"#$%&'()=-^~\\|@{}:*;+?_<>,./", "UTF-8");
                Pattern p = Pattern.compile(regex);
                assertTrue(p.matcher("!&quot;#$%&amp;&#39;()=-^~\\|@{}:*;+?_&lt;&gt;,./").matches());
            }
            {
                String regex = MatchUtil.toSmartMatch("!\"#$%&'()=-^~\\|@{}:*;+?_<>,./", "UTF-8");
                Pattern p = Pattern.compile(regex);
                assertTrue(p.matcher("\\u0021\\u0022\\u0023\\u0024\\u0025\\u0026\\u0027\\u0028\\u0029\\u003d\\u002d\\u005e\\u007e\\u005c\\u007c\\u0040\\u007b\\u007d\\u003a\\u002a\\u003b\\u002b\\u003f\\u005f\\u003c\\u003e\\u002c\\u002e\\u002f").matches());
            }
            {
                String regex = MatchUtil.toSmartMatch("!\"#$%&'()=-^~\\|@{}:*;+?_<>,./", "UTF-8");
                Pattern p = Pattern.compile(regex);
                assertTrue(p.matcher("\\x21\\x22\\x23\\x24\\x25\\x26\\x27\\x28\\x29\\x3d\\x2d\\x5e\\x7e\\x5c\\x7c\\x40\\x7b\\x7d\\x3a\\x2a\\x3b\\x2b\\x3f\\x5f\\x3c\\x3e\\x2c\\x2e\\x2f").matches());
            }
            {
                String regex = MatchUtil.toSmartMatch("<script>alert(/0/)</script>!\"#$%&'()=-^~\\|@{}:*;+?_<>,./", "UTF-8");
                Pattern p = Pattern.compile(regex);
                assertTrue(p.matcher("<script>alert(/0/)</script>!\"#$%&'()=-^~\\|@{}:*;+?_<>,./").matches());
            }
            {
                String regex = MatchUtil.toSmartMatch("<script>alert(/0/)</script>!\"#$%&'()=-^~\\|@{}:*;+?_<>,./", "UTF-8");
                Pattern p = Pattern.compile(regex);
                assertTrue(p.matcher("%3c%73%63%72%69%70%74%3e%61%6c%65%72%74%28%2f%30%2f%29%3c%2f%73%63%72%69%70%74%3e!\"#$%&'()=-^~\\|@{}:*;+?_<>,./").matches());
            }
            {
                String regex = MatchUtil.toSmartMatch("<script>alert(/0/)</script>!\"#$%&'()=-^~\\|@{}:*;+?_<>,./", "UTF-8");
                Pattern p = Pattern.compile(regex);
                assertTrue(p.matcher("%3c%73%63%72%69%70%74%3e%61%6c%65%72%74%28%2f%30%2f%29%3c%2f%73%63%72%69%70%74%3e\\x21\\x22\\x23\\x24\\x25\\x26\\x27\\x28\\x29\\x3d\\x2d\\x5e\\x7e\\x5c\\x7c\\x40\\x7b\\x7d\\x3a\\x2a\\x3b\\x2b\\x3f\\x5f\\x3c\\x3e\\x2c\\x2e\\x2f").matches());
            }
            {
                String expValue = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
                String regex = MatchUtil.toSmartMatch(expValue, "UTF-8");
                Pattern p = Pattern.compile(regex);
                assertTrue(p.matcher(expValue).matches());
            }
            {
                String expValue = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
                char[] ch = expValue.toCharArray();
                for (char c : ch) {
                    String regex = MatchUtil.toSmartMatch(Character.toString(c), "UTF-8");
                    Pattern p = Pattern.compile(regex);
                    System.out.println("ch:" + Character.toString(c));
                    assertTrue(p.matcher(Character.toString(c)).matches());
                }
            }

        } catch (UnsupportedEncodingException ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            fail();
        }
    }

    /**
     * Test of containsMailAddress method, of class SensitiveMatcher.
     */
    @Test
    public void testContainsMailAddress() {
        assertEquals(true, MatchUtil.containsMailAddress("test@example.com"));
        assertEquals(false, MatchUtil.containsMailAddress("test.example.com"));
        assertEquals(false, MatchUtil.containsMailAddress("test..example.com"));
        assertEquals(true, MatchUtil.containsMailAddress("test@example@com"));  // email 形式を含むのためTrueになる
    }

    /**
     * Test of containsCreditCard method, of class SensitiveMatcher.
     * https://www.find-job.net/startup/dummy-2013
     */
    @Test
    public void testContainsCreditCard() {
        System.out.println("containsCreditCard");
        String[] words = new String[]{
            // Visa
            "4111111111111111",
            "4242424242424242",
            "4012888888881881",
            "4222222222222",
            // Master Card
            "5555555555554444",
            "5105105105105100",
            "5431111111111111",
            "5111111111111118",
            // JCB
            "3530111333300000",
            "3566002020360505",
            // American Express
            "378282246310005",
            "371449635398431",
            "341111111111111",
            "378734493671000",
            // Diners Club
            "30569309025904",
            "38520000023237",
            // Discover Card
            //            "6111111111111116",
            "6011111111111117",
            "6011000990139424",
            "6011601160116611"
        };
        for (String word : words) {
            System.out.println(word);
            boolean expResult = true;
            boolean result = MatchUtil.containsCreditCard(word);
            assertEquals(expResult, result);
        }
    }

}
