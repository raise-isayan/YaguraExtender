package extension.helpers;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.chrono.IsoChronology;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.format.ResolverStyle;
import java.time.format.SignStyle;
import java.time.temporal.ChronoField;
import java.time.temporal.TemporalAccessor;
import java.time.temporal.TemporalQueries;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
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
public class DateUtilTest {

    public DateUtilTest() {
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

    public static final DateTimeFormatter RFC_1123_DATE_TIME_HYPHEN;

    static {
        Map<Long, String> dow = new HashMap<>();
        dow.put(1L, "Mon");
        dow.put(2L, "Tue");
        dow.put(3L, "Wed");
        dow.put(4L, "Thu");
        dow.put(5L, "Fri");
        dow.put(6L, "Sat");
        dow.put(7L, "Sun");
        Map<Long, String> moy = new HashMap<>();
        moy.put(1L, "Jan");
        moy.put(2L, "Feb");
        moy.put(3L, "Mar");
        moy.put(4L, "Apr");
        moy.put(5L, "May");
        moy.put(6L, "Jun");
        moy.put(7L, "Jul");
        moy.put(8L, "Aug");
        moy.put(9L, "Sep");
        moy.put(10L, "Oct");
        moy.put(11L, "Nov");
        moy.put(12L, "Dec");
        DateTimeFormatterBuilder builder = new DateTimeFormatterBuilder();
        RFC_1123_DATE_TIME_HYPHEN = builder.parseCaseInsensitive()
                .parseLenient()
                .optionalStart()
                .appendText(ChronoField.DAY_OF_WEEK, dow)
                .appendLiteral(", ")
                .optionalEnd()
                .appendValue(ChronoField.DAY_OF_MONTH, 1, 2, SignStyle.NOT_NEGATIVE)
                .appendLiteral('-')
                .appendText(ChronoField.MONTH_OF_YEAR, moy)
                .appendLiteral('-')
                .appendValue(ChronoField.YEAR, 4) // 2 digit year not handled
                .appendLiteral(' ')
                .appendValue(ChronoField.HOUR_OF_DAY, 2)
                .appendLiteral(':')
                .appendValue(ChronoField.MINUTE_OF_HOUR, 2)
                .optionalStart()
                .appendLiteral(':')
                .appendValue(ChronoField.SECOND_OF_MINUTE, 2)
                .optionalEnd()
                .appendLiteral(' ')
                .appendOffset("+HHMM", "GMT") // should handle UT/Z/EST/EDT/CST/CDT/MST/MDT/PST/MDT
                .toFormatter().withResolverStyle(ResolverStyle.SMART).withChronology(IsoChronology.INSTANCE);
    }

    /**
     * Test of parseZonedDateTimeDefault method, of class DateUtil.
     */
    @Test
    public void testParseZonedDateTimeDefault() {
        System.out.println("parseZonedDateTimeDefault");
        {
            String value = "Sun, 08 May 2022 04:06:13 GMT";
            ZonedDateTime defvalue = ZonedDateTime.of(2015, 10, 12, 2, 1, 0, 0, ZoneOffset.UTC);
            ZonedDateTime expResult = ZonedDateTime.of(2022, 5, 8, 4, 6, 13, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseZonedDateTimeDefault(value, defvalue);
            assertEquals(DateTimeFormatter.RFC_1123_DATE_TIME.format(expResult), DateTimeFormatter.RFC_1123_DATE_TIME.format(result));
        }
        {
            String value = "Date: Sun, 08 May 2022 04:06:13 GMT";
            ZonedDateTime defvalue = ZonedDateTime.of(2015, 10, 12, 2, 1, 0, 0, ZoneOffset.UTC);
            ZonedDateTime expResult = ZonedDateTime.of(2015, 10, 12, 2, 1, 0, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseZonedDateTimeDefault(value, defvalue);
            assertEquals(DateTimeFormatter.RFC_1123_DATE_TIME.format(expResult), DateTimeFormatter.RFC_1123_DATE_TIME.format(result));
        }
    }

    /**
     * Test of parseHttpDate method, of class DateUtil.
     */
    @Test
    public void testParseHttpDate() {
        System.out.println("parseHttpDate");
        ZonedDateTime expResult = ZonedDateTime.of(2022, 5, 8, 4, 6, 13, 0, ZoneOffset.UTC);
        {
            String dateStr = " Sun,  8  May  2022  04:06:13 GMT ";
            ZonedDateTime result = DateUtil.parseSmartHttpDate(dateStr);
            assertEquals(DateTimeFormatter.RFC_1123_DATE_TIME.format(expResult), DateTimeFormatter.RFC_1123_DATE_TIME.format(result));
        }
        {
            String dateStr = "8 May 2022 04:06:13 GMT";
            ZonedDateTime result = ZonedDateTime.from(DateTimeFormatter.RFC_1123_DATE_TIME.parse(dateStr.trim()));
            assertEquals(DateTimeFormatter.RFC_1123_DATE_TIME.format(expResult), DateTimeFormatter.RFC_1123_DATE_TIME.format(result));
        }
        {
            String dateStr = "8-May-2022 04:06:13 GMT";
            ZonedDateTime result = ZonedDateTime.from(RFC_1123_DATE_TIME_HYPHEN.parse(dateStr.trim()));
            assertEquals(DateTimeFormatter.RFC_1123_DATE_TIME.format(expResult), DateTimeFormatter.RFC_1123_DATE_TIME.format(result));
        }
    }

    private final static DateTimeFormatter SMART_RFC_1123_FORMATTER = DateTimeFormatter.ofPattern("[[eee, ]d MMM uuuu[ H:m:s] zz][[eee, ]d-MMM-uuuu[ H:m:s] zz][[eee, ]d MMM uuuu[ H:m:s][ ZZ]][[eee, ]d-MMM-uuuu[ H:m:s] ZZ]", Locale.ENGLISH);

    final static DateTimeFormatter SMART_RFC_1123_FMT = DateTimeFormatter.ofPattern("[[eee, ]d MMM uuuu[ H[:m[:s]]] zz][[eee, ]d-MMM-uuuu[ H[:m[:s]]] zz][[eee, ]d MMM uuuu[ H[:m[:s]]][ ZZ]][[eee, ]d-MMM-uuuu[ H[:m[:s]]][ ZZ]]", Locale.ENGLISH);

    final static DateTimeFormatter SMART_ISO_8601_FMT = DateTimeFormatter.ofPattern("uuuu-M-d['T'H[:m[:s]]]XXX", Locale.ENGLISH);

    /**
     * Test of parseSmartHttpDate method, of class DateUtil.
     */
    @Test
    public void testParseSmartHttpDate() {
        System.out.println("parseSmartHttpDate");
        {
            String dateStr = " Sun, 8 May 2022 04:06:13 GMT ";
            ZonedDateTime expResult = ZonedDateTime.of(2022, 5, 8, 4, 6, 13, 0, ZoneOffset.UTC);
            ZonedDateTime result = ZonedDateTime.from(SMART_RFC_1123_FORMATTER.parse(dateStr.trim()));
            assertEquals(DateTimeFormatter.RFC_1123_DATE_TIME.format(expResult), DateTimeFormatter.RFC_1123_DATE_TIME.format(result));
        }
        {
            String dateStr = "8 May 2022 04:06:13 GMT";
            ZonedDateTime expResult = ZonedDateTime.of(2022, 5, 8, 4, 6, 13, 0, ZoneOffset.UTC);
            ZonedDateTime result = ZonedDateTime.from(SMART_RFC_1123_FORMATTER.parse(dateStr.trim()));
            assertEquals(DateTimeFormatter.RFC_1123_DATE_TIME.format(expResult), DateTimeFormatter.RFC_1123_DATE_TIME.format(result));
        }
        {
            String dateStr = "Sun, 8 May 2022 04:06:13 +0900";
            ZonedDateTime expResult = ZonedDateTime.of(2022, 5, 8, 4, 6, 13, 0, ZoneOffset.UTC);
            TemporalAccessor tm = SMART_RFC_1123_FORMATTER.parse(dateStr.trim());
            if (tm.isSupported(ChronoField.OFFSET_SECONDS)) {
                ZonedDateTime result = ZonedDateTime.from(tm);
                System.out.println(result.toEpochSecond());
                assertEquals(expResult.toEpochSecond(), result.minusHours(-9).toEpochSecond());
            } else {
                fail();
            }
        }
        {
            String dateStr = "Sat, 4 Jun 2022 11:20:00 +0900";
            TemporalAccessor tm = SMART_RFC_1123_FORMATTER.parse(dateStr.trim());
            if (tm.isSupported(ChronoField.OFFSET_SECONDS)) {
                System.out.println("ZONE:");
            } else {
                System.out.println("NOT ZONE:");
            }
        }
        {
            String dateStr = "8 May 2022 GMT";
            TemporalAccessor tm = SMART_RFC_1123_FORMATTER.parse(dateStr.trim());
            int hour = 0;
            int minute = 0;
            int second = 0;
            ZoneId zone = ZoneId.of("GMT");
            if (tm.isSupported(ChronoField.HOUR_OF_DAY)) {
                hour = tm.get(ChronoField.HOUR_OF_DAY);
            }
            if (tm.isSupported(ChronoField.MINUTE_OF_HOUR)) {
                minute = tm.get(ChronoField.MINUTE_OF_HOUR);
            }
            if (tm.isSupported(ChronoField.SECOND_OF_MINUTE)) {
                second = tm.get(ChronoField.SECOND_OF_MINUTE);
            }
            if (tm.isSupported(ChronoField.OFFSET_SECONDS)) {
                zone = ZoneOffset.ofTotalSeconds(tm.get(ChronoField.OFFSET_SECONDS));
            } else if (tm.query(TemporalQueries.zone()) != null) {
                zone = tm.query(TemporalQueries.zone());
            }
            LocalDate ldt = LocalDate.from(tm);
            LocalTime ltm = LocalTime.of(hour, minute, second);
            ZonedDateTime result = LocalDateTime.of(ldt, ltm).atZone(zone);
            System.out.println("convert:" + result);
        }
        {
            String dateStr = "8 May 2022 +0900";
            TemporalAccessor tm = SMART_RFC_1123_FORMATTER.parse(dateStr.trim());
            int hour = 0;
            int minute = 0;
            int second = 0;
            ZoneId zone = ZoneId.of("GMT");
            if (tm.isSupported(ChronoField.HOUR_OF_DAY)) {
                hour = tm.get(ChronoField.HOUR_OF_DAY);
            }
            if (tm.isSupported(ChronoField.MINUTE_OF_HOUR)) {
                minute = tm.get(ChronoField.MINUTE_OF_HOUR);
            }
            if (tm.isSupported(ChronoField.SECOND_OF_MINUTE)) {
                second = tm.get(ChronoField.SECOND_OF_MINUTE);
            }
            if (tm.isSupported(ChronoField.OFFSET_SECONDS)) {
                zone = ZoneOffset.ofTotalSeconds(tm.get(ChronoField.OFFSET_SECONDS));
            } else if (tm.query(TemporalQueries.zone()) != null) {
                zone = tm.query(TemporalQueries.zone());
            }
            LocalDate ldt = LocalDate.from(tm);
            LocalTime ltm = LocalTime.of(hour, minute, second);
            ZonedDateTime result = LocalDateTime.of(ldt, ltm).atZone(zone);
            System.out.println("convert:" + result);
        }
    }

    @Test
    public void testParseSmartDate_RFC_1123() {
        System.out.println("testParseSmartDate_RFC_1123");
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 4, 11, 20, 10, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("Sat, 4 Jun 2022 11:20:10", DateUtil.SMART_RFC_1123_FMT);
            assertEquals(DateTimeFormatter.RFC_1123_DATE_TIME.format(expResult), DateTimeFormatter.RFC_1123_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 4, 11, 20, 10, 0, ZoneId.of("Asia/Tokyo"));
            ZonedDateTime result = DateUtil.parseSmartDate("Sat, 4 Jun 2022 11:20:10 JST", DateUtil.SMART_RFC_1123_FMT);
            assertEquals(DateTimeFormatter.RFC_1123_DATE_TIME.format(expResult), DateTimeFormatter.RFC_1123_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 4, 11, 20, 10, 0, ZoneOffset.ofHours(9));
            ZonedDateTime result = DateUtil.parseSmartDate("Sat, 4 Jun 2022 11:20:10 +0900", DateUtil.SMART_RFC_1123_FMT);
            assertEquals(DateTimeFormatter.RFC_1123_DATE_TIME.format(expResult), DateTimeFormatter.RFC_1123_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 4, 11, 20, 0, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("Sat, 4 Jun 2022 11:20 GMT", DateUtil.SMART_RFC_1123_FMT);
            assertEquals(DateTimeFormatter.RFC_1123_DATE_TIME.format(expResult), DateTimeFormatter.RFC_1123_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 4, 11, 0, 0, 0, ZoneOffset.ofHours(9));
            ZonedDateTime result = DateUtil.parseSmartDate("Sat, 4 Jun 2022 11 +0900", DateUtil.SMART_RFC_1123_FMT);
            assertEquals(DateTimeFormatter.RFC_1123_DATE_TIME.format(expResult), DateTimeFormatter.RFC_1123_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 4, 0, 0, 0, 0, ZoneId.of("Asia/Tokyo"));
            ZonedDateTime result = DateUtil.parseSmartDate("Sat, 4 Jun 2022 JST", DateUtil.SMART_RFC_1123_FMT);
            assertEquals(DateTimeFormatter.RFC_1123_DATE_TIME.format(expResult), DateTimeFormatter.RFC_1123_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 4, 0, 0, 0, 0, ZoneOffset.ofHours(9));
            ZonedDateTime result = DateUtil.parseSmartDate("Sat, 4 Jun 2022 +0900", DateUtil.SMART_RFC_1123_FMT);
            assertEquals(DateTimeFormatter.RFC_1123_DATE_TIME.format(expResult), DateTimeFormatter.RFC_1123_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 4, 0, 0, 0, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("Sat, 4 Jun 2022", DateUtil.SMART_RFC_1123_FMT);
            assertEquals(DateTimeFormatter.RFC_1123_DATE_TIME.format(expResult), DateTimeFormatter.RFC_1123_DATE_TIME.format(result));
        }
        {
            String dateStr = "Sun,08 May 2022 04:06:13 GMT";
            ZonedDateTime expResult = ZonedDateTime.of(2022, 5, 8, 4, 6, 13, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate(dateStr, DateUtil.SMART_RFC_1123_FMT);
            assertEquals(DateTimeFormatter.RFC_1123_DATE_TIME.format(expResult), DateTimeFormatter.RFC_1123_DATE_TIME.format(result));
        }
        {
            String dateStr = "Sun,8 May 2022 4:6:3 GMT";
            ZonedDateTime expResult = ZonedDateTime.of(2022, 5, 8, 4, 6, 3, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate(dateStr, DateUtil.SMART_RFC_1123_FMT);
            assertEquals(DateTimeFormatter.RFC_1123_DATE_TIME.format(expResult), DateTimeFormatter.RFC_1123_DATE_TIME.format(result));
        }
    }

    @Test
    public void testParseSmartDate_ISO_8601() {
        System.out.println("testParseSmartDate_ISO_8601");
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 31, 43, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022-06-05T19:31:43Z", DateUtil.SMART_ISO_8601_FMT);
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 31, 43, 0, ZoneOffset.ofHours(9));
            ZonedDateTime result = DateUtil.parseSmartDate("2022-06-05T19:31:43+09:00", DateUtil.SMART_ISO_8601_FMT);
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 31, 0, 0, ZoneOffset.ofHours(9));
            ZonedDateTime result = DateUtil.parseSmartDate("2022-06-05T19:31+09:00", DateUtil.SMART_ISO_8601_FMT);
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 0, 0, 0, ZoneOffset.ofHours(9));
            ZonedDateTime result = DateUtil.parseSmartDate("2022-06-05T19+09:00", DateUtil.SMART_ISO_8601_FMT);
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 0, 0, 0, 0, ZoneOffset.ofHours(9));
            ZonedDateTime result = DateUtil.parseSmartDate("2022-06-05+09:00", DateUtil.SMART_ISO_8601_FMT);
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 31, 43, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022-06-05T19:31:43", DateUtil.SMART_ISO_8601_FMT);
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 31, 0, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022-06-05T19:31", DateUtil.SMART_ISO_8601_FMT);
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 0, 0, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022-06-05T19", DateUtil.SMART_ISO_8601_FMT);
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 0, 0, 0, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022-06-05", DateUtil.SMART_ISO_8601_FMT);
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
    }

    @Test
    public void testRegex_RFC_1123() {
        System.out.println("testRegex_RFC_1123");
        {
            String dateStr = "Sun, 08 May 2022 04:06:13 GMT";
            boolean result = DateUtil.REGEX_RFC_1123.matcher(dateStr).find();
            assertTrue(result);
        }
        {
            String dateStr = "Date: Sun, 08 May 2022 04:06:13 GMT";
            boolean result = DateUtil.REGEX_RFC_1123.matcher(dateStr).find();
            assertTrue(result);
        }
        {
            String dateStr = " Sun, 8 May 2022 04:06:13 GMT ";
            boolean result = DateUtil.REGEX_RFC_1123.matcher(dateStr).find();
            assertTrue(result);
        }
        {
            String dateStr = "8 May 2022 04:06:13 GMT";
            boolean result = DateUtil.REGEX_RFC_1123.matcher(dateStr).find();
            assertTrue(result);
        }
        {
            String dateStr = "8-May-2022 04:06:13 GMT";
            boolean result = DateUtil.REGEX_RFC_1123.matcher(dateStr).find();
            assertTrue(result);
        }
    }

    @Test
    public void testRegex_ISO_8601() {
        System.out.println("testRegex_ISO_8601");
        {
            boolean result = DateUtil.REGEX_ISO_8601.matcher("2022-06-05T19:31:43Z").find();
            assertTrue(result);
        }
        {
            boolean result = DateUtil.REGEX_ISO_8601.matcher("2022-06-05T19:31:43+09:00").find();
            assertTrue(result);
        }
        {
            boolean result = DateUtil.REGEX_ISO_8601.matcher("2022-06-05T19:31+09:00").find();
            assertTrue(result);
        }
        {
            boolean result = DateUtil.REGEX_ISO_8601.matcher("2022-06-05T19+09:00").find();
            assertTrue(result);
        }
        {
            boolean result = DateUtil.REGEX_ISO_8601.matcher("2022-06-05+09:00").find();
            assertTrue(result);
        }
        {
            boolean result = DateUtil.REGEX_ISO_8601.matcher("2022-06-05T19:31:43").find();
            assertTrue(result);
        }
        {
            boolean result = DateUtil.REGEX_ISO_8601.matcher("2022-06-05T19:31").find();
            assertTrue(result);
        }
        {
            boolean result = DateUtil.REGEX_ISO_8601.matcher("2022-06-05T19").find();
            assertTrue(result);
        }
        {
            boolean result = DateUtil.REGEX_ISO_8601.matcher("2022-06-05").find();
            assertTrue(result);
        }
    }

    @Test
    public void testRegex_Date() {
        System.out.println("testRegex_Date");
        // Hyphen
        {
            boolean result = DateUtil.REGEX_DATE.matcher("2022-06-05 19:31:43").find();
            assertTrue(result);
        }
        {
            boolean result = DateUtil.REGEX_DATE.matcher("2022-06-05 19:31:43").find();
            assertTrue(result);
        }
        {
            boolean result = DateUtil.REGEX_DATE.matcher("2022-06-05 19:31").find();
            assertTrue(result);
        }
        {
            boolean result = DateUtil.REGEX_DATE.matcher("2022-06-05 19").find();
            assertTrue(result);
        }
        {
            boolean result = DateUtil.REGEX_DATE.matcher("2022-06-05").find();
            assertTrue(result);
        }
        // Slash
        {
            boolean result = DateUtil.REGEX_DATE.matcher("2022/06/05 19:31:43").find();
            assertTrue(result);
        }
        {
            boolean result = DateUtil.REGEX_DATE.matcher("2022/06/05 9:31").find();
            assertTrue(result);
        }
        {
            boolean result = DateUtil.REGEX_DATE.matcher("2022/06/05 19").find();
            assertTrue(result);
        }
        {
            boolean result = DateUtil.REGEX_DATE.matcher("2022/06/05").find();
            assertTrue(result);
        }
        // Space
        {
            boolean result = DateUtil.REGEX_DATE.matcher("2022 06 05 19:31:43").find();
            assertTrue(result);
        }
        {
            boolean result = DateUtil.REGEX_DATE.matcher("2022 06 05 9:31").find();
            assertTrue(result);
        }
        {
            boolean result = DateUtil.REGEX_DATE.matcher("2022 06 05 19").find();
            assertTrue(result);
        }
        {
            boolean result = DateUtil.REGEX_DATE.matcher("2022 06 05").find();
            assertTrue(result);
        }
    }

    @Test
    public void testParseSmartDate_Separator() {
        System.out.println("testParseSmartDate_Separator");
        // Hyphen
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 31, 43, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022-06-05 19:31:43", DateUtil.SMART_DATE_SEPARATOR_FMT);
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 31, 0, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022-06-05 19:31", DateUtil.SMART_DATE_SEPARATOR_FMT);
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 0, 0, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022-06-05 19", DateUtil.SMART_DATE_SEPARATOR_FMT);
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 0, 0, 0, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022-06-05", DateUtil.SMART_DATE_SEPARATOR_FMT);
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 3, 4, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022-6-5 19:3:4", DateUtil.SMART_DATE_SEPARATOR_FMT);
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 0, 0, 0, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022-6-5", DateUtil.SMART_DATE_SEPARATOR_FMT);
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        // Slash
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 31, 43, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022/06/05 19:31:43", DateUtil.SMART_DATE_SEPARATOR_FMT);
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 31, 0, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022/06/05 19:31", DateUtil.SMART_DATE_SEPARATOR_FMT);
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 0, 0, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022/06/05 19", DateUtil.SMART_DATE_SEPARATOR_FMT);
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 0, 0, 0, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022/06/05", DateUtil.SMART_DATE_SEPARATOR_FMT);
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 3, 4, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022/6/5 19:3:4", DateUtil.SMART_DATE_SEPARATOR_FMT);
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 0, 0, 0, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022/6/5", DateUtil.SMART_DATE_SEPARATOR_FMT);
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        // Space
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 31, 43, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022 06 05 19:31:43", DateUtil.SMART_DATE_SEPARATOR_FMT);
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 31, 43, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022 06 05 19:31:43", DateUtil.SMART_DATE_SEPARATOR_FMT);
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 31, 0, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022 06 05 19:31", DateUtil.SMART_DATE_SEPARATOR_FMT);
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 0, 0, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022 06 05 19", DateUtil.SMART_DATE_SEPARATOR_FMT);
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 0, 0, 0, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022 06 05", DateUtil.SMART_DATE_SEPARATOR_FMT);
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 3, 4, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022 6 5 19:3:4", DateUtil.SMART_DATE_SEPARATOR_FMT);
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 0, 0, 0, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022 6 5", DateUtil.SMART_DATE_SEPARATOR_FMT);
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
    }

    @Test
    public void testParseSmartDate() {
        // ISO-8601
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 31, 43, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022-06-05T19:31:43Z");
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 31, 43, 0, ZoneOffset.ofHours(9));
            ZonedDateTime result = DateUtil.parseSmartDate("2022-06-05T19:31:43+09:00");
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 31, 0, 0, ZoneOffset.ofHours(9));
            ZonedDateTime result = DateUtil.parseSmartDate("2022-06-05T19:31+09:00");
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 0, 0, 0, ZoneOffset.ofHours(9));
            ZonedDateTime result = DateUtil.parseSmartDate("2022-06-05T19+09:00");
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 0, 0, 0, 0, ZoneOffset.ofHours(9));
            ZonedDateTime result = DateUtil.parseSmartDate("2022-06-05+09:00");
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 31, 43, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022-06-05T19:31:43");
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 31, 0, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022-06-05T19:31");
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 0, 0, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022-06-05T19");
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 0, 0, 0, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022-06-05");
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }

        // Hyphen
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 31, 43, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022-06-05 19:31:43");
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 31, 0, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022-06-05 19:31");
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 0, 0, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022-06-05 19");
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 0, 0, 0, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022-06-05");
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 3, 4, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022-6-5 19:3:4");
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 0, 0, 0, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022-6-5");
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        // Slash
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 31, 43, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022/06/05 19:31:43");
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 31, 0, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022/06/05 19:31");
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 0, 0, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022/06/05 19");
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 0, 0, 0, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022/06/05");
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 3, 4, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022/6/5 19:3:4");
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 0, 0, 0, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022/6/5");
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        // Space
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 31, 43, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022 06 05 19:31:43");
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 31, 43, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022 06 05 19:31:43");
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 31, 0, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022 06 05 19:31");
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 0, 0, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022 06 05 19");
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 0, 0, 0, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022 06 05");
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 19, 3, 4, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022 6 5 19:3:4");
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            ZonedDateTime expResult = ZonedDateTime.of(2022, 6, 5, 0, 0, 0, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate("2022 6 5");
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        // RFC_1123
        {
            String dateStr = "Sun, 08 May 2022 04:06:13 GMT";
            ZonedDateTime expResult = ZonedDateTime.of(2022, 5, 8, 4, 6, 13, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate(dateStr);
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            String dateStr = "Date: Sun, 08 May 2022 04:06:13 GMT";
            ZonedDateTime expResult = ZonedDateTime.of(2022, 5, 8, 4, 6, 13, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate(dateStr);
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            String dateStr = " Sun, 8  May  2022  04:06:13 GMT ";
            ZonedDateTime expResult = ZonedDateTime.of(2022, 5, 8, 4, 6, 13, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate(dateStr);
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            String dateStr = " Sun, 8 May 2022 04:06:13 GMT ";
            ZonedDateTime expResult = ZonedDateTime.of(2022, 5, 8, 4, 6, 13, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate(dateStr);
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            String dateStr = "8 May 2022 04:06:13 GMT";
            ZonedDateTime expResult = ZonedDateTime.of(2022, 5, 8, 4, 6, 13, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate(dateStr);
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }
        {
            String dateStr = "8-May-2022 04:06:13 GMT";
            ZonedDateTime expResult = ZonedDateTime.of(2022, 5, 8, 4, 6, 13, 0, ZoneOffset.UTC);
            ZonedDateTime result = DateUtil.parseSmartDate(dateStr);
            assertEquals(DateTimeFormatter.ISO_DATE_TIME.format(expResult), DateTimeFormatter.ISO_DATE_TIME.format(result));
        }

    }
}
