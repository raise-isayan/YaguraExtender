package extension.helpers;

import java.nio.ByteOrder;
import java.text.ParseException;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author isayan
 */
public class IpUtil {

    private final static String IPv4_PATTERN = "(25[0-5]|2[0-4][0-9]|[01]?[0-9]{1,2})\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9]{1,2})\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9]{1,2})\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9]{1,2})";
    private final static String IPv6_PATTERN = "([0-9a-f]{1,4}(:[0-9a-f]{1,4}){7})|::"
            + "|:(:[0-9a-f]{1,4}){1,7}|([0-9a-f]{1,4}:){1,7}:"
            + "|([0-9a-f]{1,4}:){1}(:[0-9a-f]{1,4}){1,6}|([0-9a-f]{1,4}:){2}(:[0-9a-f]{1,4}){1,5}"
            + "|([0-9a-f]{1,4}:){3}(:[0-9a-f]{1,4}){1,4}|([0-9a-f]{1,4}:){4}(:[0-9a-f]{1,4}){1,3}"
            + "|([0-9a-f]{1,4}:){5}(:[0-9a-f]{1,4}){1,2}|([0-9a-f]{1,4}:){6}(:[0-9a-f]{1,4}){1}";

    private final static Pattern IPv4_ADDR = Pattern.compile(IPv4_PATTERN);
    private final static Pattern IPv6_ADDR = Pattern.compile("(" + IPv6_PATTERN + ")" + "|" + "\\[(" + IPv6_PATTERN + ")\\]");

    private final static Pattern IPv4_HEX = Pattern.compile("([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})");
    private final static Pattern IPv6_HEX = Pattern.compile("([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{4})");

    private final static Pattern IPv4_VALID = Pattern.compile("(?<ip>" + IPv4_PATTERN + ")(:(?<port>\\d+))?");

    private final static long CLASS_A_MASK = 0xFF000000L;
    private final static long CLASS_A_NET = 0x0A000000L; // 10.0.0.0/8
    private final static long CLASS_B_MASK = 0xFFF00000L;
    private final static long CLASS_B_NET = 0xAC100000L; // 172.16.0.0/12
    private final static long CLASS_C_MASK = 0xFFFF0000L;
    private final static long CLASS_C_NET = 0xC0A80000L; // 192.168.0.0/16
    private final static long LINK_LOCAL_MASK = 0xFFFF0000L;
    private final static long LINK_LOCAL_NET = 0x0A9FE0000L; // 169.254.0.0/16

    public static boolean isIPv4Valid(String ipAddr) {
        Matcher m = IPv4_VALID.matcher(ipAddr);
        if (m.matches()) {
            String address = m.group("ip");
            String port = m.group("port");
            if (port == null) {
                return isIPv4Address(address);
            } else {
                return isIPv4Valid(address, ConvertUtil.parseIntDefault(port, -1));
            }
        }
        return false;
    }

    public static boolean isIPv4Valid(String ip_addr, int port) {
        return (isIPv4Address(ip_addr) && 0 <= port && port < 65536);
    }

    public static boolean isIPv6Valid(String ip_addr, int port) {
        return (isIPv6Address(ip_addr) && 0 <= port && port < 65536);
    }

    public static boolean isIPv4Address(String ip_addr) {
        return ip_addr != null && IPv4_ADDR.matcher(ip_addr).matches();
    }

    public static boolean isIPv6Address(String ip_addr) {
        return ip_addr != null && IPv6_ADDR.matcher(ip_addr).matches();
    }

    /**
     * IPv4アドレスのパース
     * IPv4 address は厳密には以下の形式も解釈するがこの関数では考慮しない 192.168.1
     * 192.11010049 3232235521
     * @param ipv4Addr
     * @return
     * @throws java.text.ParseException
     */
    public static byte[] parseIPv4AddressByte(String ipv4Addr) throws ParseException {
        Matcher m = IPv4_ADDR.matcher(ipv4Addr);
        if (m.matches()) {
            return new byte[]{(byte) Integer.parseInt(m.group(1)), (byte) Integer.parseInt(m.group(2)), (byte) Integer.parseInt(m.group(3)), (byte) Integer.parseInt(m.group(4))};
        }
        throw new ParseException("IPv4 format Error:", 0);
    }

    /**
     * IPv6アドレスのパース
     * @param ipAddr
     * @return
     * @throws java.text.ParseException
     */
    public static byte[] parseIPv6AddressByte(String ipAddr) throws ParseException {
        Matcher m = IPv6_ADDR.matcher(ipAddr);
        if (m.matches()) {
            // 省略
            if (ipAddr.contains("::")) {
                byte ip[] = new byte[16];
                Arrays.fill(ip, (byte) 0);
                String ipParts[] = ipAddr.split("::");
                if (ipParts.length == 2) {
                    // 前半と後半
                    byte ipPart0[] = parseIPv6Part(ipParts[0]);
                    byte ipPart1[] = parseIPv6Part(ipParts[1]);
                    System.arraycopy(ipPart0, 0, ip, 0, ipPart0.length);
                    System.arraycopy(ipPart1, 0, ip, ip.length - ipPart1.length, ipPart1.length);
                    return ip;
                } else if (ipParts.length == 1) {
                    // 前半
                    byte ipPart0[] = parseIPv6Part(ipParts[0]);
                    System.arraycopy(ipPart0, 0, ip, 0, ipPart0.length);
                    return ip;
                } else if (ipParts.length == 0) {
                    // ::
                    return ip;
                }
            } else {
                String ipPart = m.group(1);
                return parseIPv6Part(ipPart);
            }
        }
        throw new ParseException("IPv6 format Error:", 0);
    }

    private static byte[] parseIPv6Part(String ipPart) {
        if (!ipPart.isEmpty()) {
            String ipParts[] = ipPart.split(":");
            byte[] ip = new byte[ipParts.length * 2];
            for (int i = 0; i < ipParts.length; i++) {
                int part = Integer.parseInt(ipParts[i], 16);
                ip[i * 2 + 0] = (byte) (part >> 8 & 0xff);
                ip[i * 2 + 1] = (byte) (part & 0xff);
            }
            return ip;
        } else {
            return new byte[0];
        }
    }

    public static boolean isPrivateIP(String ipAddr) {
        try {
            // portを分離
            String ip[] = ipAddr.split(":", 2);
            long ip_decimal = IPv4ToDecimal(ip[0], ByteOrder.BIG_ENDIAN);
            return ((ip_decimal & CLASS_A_MASK) == CLASS_A_NET)
                    || ((ip_decimal & CLASS_B_MASK) == CLASS_B_NET)
                    || ((ip_decimal & CLASS_C_MASK) == CLASS_C_NET);
        } catch (ParseException ex) {
            return false;
        }
    }

    public static boolean isLinkLocalIP(String ipAddr) {
        try {
            // portを分離
            String ip[] = ipAddr.split(":", 2);
            long ip_decimal = IPv4ToDecimal(ip[0], ByteOrder.BIG_ENDIAN);
            return ((ip_decimal & LINK_LOCAL_MASK) == LINK_LOCAL_NET);
        } catch (ParseException ex) {
            return false;
        }
    }

    public static long IPv4ToDecimal(String ipAddr, ByteOrder order) throws ParseException {
        Matcher m = IPv4_ADDR.matcher(ipAddr);
        if (m.matches()) {
            if (order.equals(ByteOrder.BIG_ENDIAN)) {
                String ip_hex = String.format("%02x%02x%02x%02x", Integer.valueOf(m.group(1)), Integer.parseInt(m.group(2)), Integer.parseInt(m.group(3)), Integer.parseInt(m.group(4)));
                return Long.parseLong(ip_hex, 16);
            } else {
                String ip_hex = String.format("%02x%02x%02x%02x", Integer.valueOf(m.group(4)), Integer.parseInt(m.group(3)), Integer.parseInt(m.group(2)), Integer.parseInt(m.group(1)));
                return Long.parseLong(ip_hex, 16);
            }
        }
        throw new ParseException("IPv4 format Error:", 0);
    }

    public static String decimalToIPv4(long ipDecimal, ByteOrder order) {
        return hexToIPv4(String.format("%08x", ipDecimal), order);
    }

    public static String hexToIPv4(String ipAddr, ByteOrder order) {
        String ipv4 = null;
        Matcher m = IPv4_HEX.matcher(ipAddr);
        if (m.matches()) {
            if (order.equals(ByteOrder.BIG_ENDIAN)) {
                ipv4 = String.format("%d.%d.%d.%d",
                        Integer.parseInt(m.group(1), 16),
                        Integer.parseInt(m.group(2), 16),
                        Integer.parseInt(m.group(3), 16),
                        Integer.parseInt(m.group(4), 16));
            } else {
                ipv4 = String.format("%d.%d.%d.%d",
                        Integer.parseInt(m.group(4), 16),
                        Integer.parseInt(m.group(3), 16),
                        Integer.parseInt(m.group(2), 16),
                        Integer.parseInt(m.group(1), 16));
            }
        }
        return ipv4;
    }

    public static String hexToIPv6(String ipAddr) {
        String ipv6 = null;
        Matcher m = IPv6_HEX.matcher(ipAddr);
        if (m.matches()) {
            return String.format("[%s:%s:%s:%s:%s:%s:%s:%s]", m.group(1), m.group(2), m.group(3), m.group(4), m.group(5), m.group(6), m.group(7), m.group(8));
        }
        return ipv6;
    }

    public static int decimalToPort(int portDecimal, ByteOrder order) {
        String port_hex = String.format("%04x", portDecimal);
        if (order.equals(ByteOrder.BIG_ENDIAN)) {
            return Integer.parseInt(String.format("%s%s", port_hex.substring(0, 2), port_hex.substring(2, 4)), 16);
        } else {
            return Integer.parseInt(String.format("%s%s", port_hex.substring(2, 4), port_hex.substring(0, 2)), 16);
        }
    }

    public static String ipv4ToHex(int dec1, int dec2, int dec3, int dec4) {
        return String.format("0x%02x%02x%02x%02x", dec1, dec2, dec3, dec4);
    }

    public static String ipv4ToDotHex(int dec1, int dec2, int dec3, int dec4) {
        return String.format("0x%02x.0x%02x.0x%02x.0x%02x", dec1, dec2, dec3, dec4);
    }

    public static String ipv4ToOct(int dec1, int dec2, int dec3, int dec4) {
        String hexIP = String.format("%02x%02x%02x%02x", dec1, dec2, dec3, dec4);
        return String.format("0%o", Long.parseLong(hexIP, 16));
    }

    public static String ipv4ToDotOct(int dec1, int dec2, int dec3, int dec4) {
        return String.format("0%03o.0%03o.0%03o.0%03o", dec1, dec2, dec3, dec4);
    }

    public static String ipv4ToInt(int dec1, int dec2, int dec3, int dec4) {
        String hexIP = String.format("%02x%02x%02x%02x", dec1, dec2, dec3, dec4);
        return Long.toString(Long.parseLong(hexIP, 16));
    }

}
