package yagura.model;

import extension.burp.FilterProperty;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 *
 * @author isayan
 */
public class OptoinPropertyTest {

    public OptoinPropertyTest() {
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

    /**
     */
    @Test
    public void testLinkedHashMap() {
        Map<String,String> synclink = Collections.synchronizedMap(new LinkedHashMap<String,String>());
        synclink.put("n5", "e");
        synclink.put("n4", "d");
        synclink.put("n3", "c");
        synclink.put("n2", "b");
        synclink.put("n1", "a");
        synclink.put("n3", "c");
        synclink.put("n1", "e");
        synclink.put("n4", "b");
        synclink.put("n2", "d");
        synclink.put("n5", "a");
        Map<String,String> synclink2 = Collections.synchronizedMap(new LinkedHashMap<String,String>());
        synclink2.put("n3", "c");
        synclink2.put("n1", "e");
        synclink2.put("n4", "b");
        synclink2.put("n2", "d");
        synclink2.put("n5", "a");

        Map<String,String> link = new LinkedHashMap<String,String>();
        link.put("5", "e");
        link.put("4", "d");
        link.put("3", "c");
        link.put("2", "b");
        link.put("1", "a");
        link.put("1", "e");
        link.put("2", "d");
        link.put("3", "c");
        link.put("4", "b");
        link.put("5", "a");
        for (String k : link.keySet()) {
            System.out.println("origin:" + k);
        }
        Map<String,String> newLink = new LinkedHashMap<String,String>();
        newLink.putAll(link);
        for (String k : newLink.keySet()) {
            System.out.println("newLink:" + k);
        }

        Map<String,String> newSyncLink = new LinkedHashMap<String,String>();
        newSyncLink.putAll(synclink);
        for (String k : newSyncLink.keySet()) {
            System.out.println("newSyncLink:" + k);
        }
        newSyncLink.clear();
        newSyncLink.putAll(synclink);
        for (String k : newSyncLink.keySet()) {
            System.out.println("newSyncLink2:" + k);
        }
        Map<String, String> filterMap = Collections.synchronizedMap(new LinkedHashMap<String, String>(16, (float) 0.75, true));
        filterMap.putAll(synclink);
        for (String k : filterMap.keySet()) {
            System.out.println("curSyncLinkMap:" + k);
        }
        filterMap.clear();
        filterMap.putAll(synclink2);
        for (String k : filterMap.keySet()) {
            System.out.println("newSyncLinkMap:" + k);
        }

    }

}
