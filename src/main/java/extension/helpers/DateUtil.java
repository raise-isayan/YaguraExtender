package extension.helpers;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoField;
import java.time.temporal.TemporalAccessor;
import java.time.temporal.TemporalQueries;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author isayan
 */
public class DateUtil {

    /**
     * 文字列をZonedDateTime型に変換
     *
     * @param value 対象文字列
     * @param defvalue 変換できなかった場合のデフォルト値
     * @return 変換後のZonedDateTime
     */
    public static ZonedDateTime parseZonedDateTimeDefault(String value, ZonedDateTime defvalue) {
        try {
            return parseHttpDate(value);
        } catch (DateTimeParseException ex) {
            return defvalue;
        }
    }

    private final static DateTimeFormatter RFC_1123_FORMATTER = DateTimeFormatter.ofPattern("[eee, d MMM uuuu H:m:s z][eee, d-MMM-uuuu H:m:s z][eee, d MMM uuuu H:m:s Z][eee, d-MMM-uuuu H:m:s Z]", Locale.ENGLISH);

    public static ZonedDateTime parseHttpDate(String dateStr) {
        return ZonedDateTime.from(RFC_1123_FORMATTER.parse(dateStr.trim()));
    }

    public static String valueOfHttpDate(ZonedDateTime zdtm) {
        return DateTimeFormatter.RFC_1123_DATE_TIME.format(zdtm);
    }

    public static ZonedDateTime parseSmartHttpDate(String dateStr) {
        return parseHttpDate(normalizeHttpDate(dateStr));
    }

    public static LocalDateTime parseHttpDateAsLocal(String dateStr, ZoneId zoneID) {
        return parseHttpDate(dateStr).withZoneSameInstant(zoneID).toLocalDateTime();
    }

    private static String normalizeHttpDate(String datevalue) {
        datevalue = datevalue.replaceAll("\\s{2,}", " ");
        datevalue = datevalue.replaceAll("\\u3000", "");
        return datevalue.trim();
    }

    final static Pattern REGEX_UNIX_TIME = Pattern.compile("\\d{1,}");

    final static Pattern REGEX_DATE = Pattern.compile("\\d{1,}[/ -]\\d{1,2}[/ -]\\d{1,2}( \\d{1,2}(:\\d{1,2}(:\\d{1,2})?)?)?(Z|[+-]\\d{2}:\\d{2})?");

    final static DateTimeFormatter SMART_DATE_SEPARATOR_FMT = DateTimeFormatter.ofPattern("[uuuu-M-d[ H[:m[:s]]]][uuuu/M/d[ H[:m[:s]]]][uuuu M d[ H[:m[:s]]]]", Locale.ENGLISH);

    final static Pattern REGEX_RFC_1123 = Pattern.compile("((Mon|Tue|Wed|Thu|Fri|Sat|Sun),\\s+)?\\d{1,}[ -](Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[ -]\\d{1,}( \\d{1,2}(:\\d{1,2}(:\\d{1,2})?)?)?");

    final static DateTimeFormatter SMART_RFC_1123_FMT = DateTimeFormatter.ofPattern("[[eee,[ ]]d MMM uuuu[ H[:m[:s]]] zz][[eee, ]d-MMM-uuuu[ H[:m[:s]]] zz][[eee, ]d MMM uuuu[ H[:m[:s]]][ ZZ]][[eee, ]d-MMM-uuuu[ H[:m[:s]]][ ZZ]]", Locale.ENGLISH);

    final static Pattern REGEX_ISO_8601 = Pattern.compile("\\d{1,}-\\d{1,2}-\\d{1,2}((?<ISO>T)\\d{1,2}(:\\d{1,2}(:\\d{1,2})?)?)?(?<ZONE>Z|[+-]\\d{2}:\\d{2})?");

    final static DateTimeFormatter SMART_ISO_8601_FMT = DateTimeFormatter.ofPattern("uuuu-M-d['T'H[:m[:s]]][XXX]", Locale.ENGLISH);

    public static ZonedDateTime parseSmartDate(String dateStr) {
        dateStr = normalizeHttpDate(dateStr);
        Matcher m1 = REGEX_ISO_8601.matcher(dateStr);
        if (m1.find()) {
            if (m1.group("ISO") != null || m1.group("ZONE") != null) {
                return parseSmartDate(m1.group(0), SMART_ISO_8601_FMT);
            }
        }
        Matcher m2 = REGEX_DATE.matcher(dateStr);
        if (m2.find()) {
            return parseSmartDate(m2.group(0), SMART_DATE_SEPARATOR_FMT);
        }
        Matcher m3 = REGEX_RFC_1123.matcher(dateStr);
        if (m3.find()) {
            return parseSmartDate(m3.group(0), SMART_RFC_1123_FMT);
        }
        throw new DateTimeParseException("SmartDate parser error:", dateStr, 0);
    }

    protected static ZonedDateTime parseSmartDate(String dateStr, DateTimeFormatter date_fmt) {
        TemporalAccessor ta = date_fmt.parse(dateStr.trim());
        int hour = 0;
        int minute = 0;
        int second = 0;
        ZoneId zoneId = ZoneOffset.UTC;
        if (ta.isSupported(ChronoField.HOUR_OF_DAY)) {
            hour = ta.get(ChronoField.HOUR_OF_DAY);
        }
        if (ta.isSupported(ChronoField.MINUTE_OF_HOUR)) {
            minute = ta.get(ChronoField.MINUTE_OF_HOUR);
        }
        if (ta.isSupported(ChronoField.SECOND_OF_MINUTE)) {
            second = ta.get(ChronoField.SECOND_OF_MINUTE);
        }
        if (ta.isSupported(ChronoField.OFFSET_SECONDS)) {
            zoneId = ZoneOffset.ofTotalSeconds(ta.get(ChronoField.OFFSET_SECONDS));
        } else if (ta.query(TemporalQueries.zone()) != null) {
            zoneId = ta.query(TemporalQueries.zone());
        }
        LocalDate ldt = LocalDate.from(ta);
        LocalTime ltm = LocalTime.of(hour, minute, second);
        return LocalDateTime.of(ldt, ltm).atZone(zoneId);
    }

}
