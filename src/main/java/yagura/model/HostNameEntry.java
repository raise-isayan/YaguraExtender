package yagura.model;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
/**
 *
 * @author isayan
 */
public class HostNameEntry {

    private String ipAddress;
    private String hostName;

    public HostNameEntry(String Address, String hostName) {
        this.ipAddress = Address;
        this.hostName = hostName;
    }

    /**
     * @return the ipAddresses
     */
    public String getIPAddress() {
        return ipAddress;
    }

    public InetAddress asInetAddress() throws UnknownHostException {
        return InetAddress.getByName(ipAddress);
    }

    /**
     * @return the hostName
     */
    public String getHostName() {
        return hostName;
    }

    public boolean isValidIP() {
        try {
            return (asInetAddress() instanceof InetAddress);
        } catch (UnknownHostException ex) {
            return false;
        }
    }

    public boolean isIPv4() {
        try {
            return (asInetAddress() instanceof Inet4Address);
        } catch (UnknownHostException ex) {
            return false;
        }
    }

    public boolean isIPv6() {
        try {
            return (asInetAddress() instanceof Inet6Address);
        } catch (UnknownHostException ex) {
            return false;
        }
    }

}
