package yagura.external;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 *
 * @author isayan
 */
public class FormatUtil {
       
    private final static Pattern URL_TYPE = Pattern.compile("^https?://.");
    private final static Pattern JSON_TYPE = Pattern.compile("[\\s\r\n]*((\\[(.*)\\])|(\\{(.*)\\}))[\\s\r\n]*", Pattern.DOTALL);
    private final static Pattern XML_TYPE = Pattern.compile("^[\\s\r\n]*((<!(.*?)>)|(<\\?(.*?)\\?>)|(<\\w+>)|(<!--(.*?)-->}))", Pattern.DOTALL);
    
    public static boolean isURL(String plainURL) {
        Matcher m = URL_TYPE.matcher(plainURL);
        return m.find();
    }

    public static boolean isXML(String plainXML) {
        Matcher m = XML_TYPE.matcher(plainXML);
        return m.lookingAt();
    }
    
    public static boolean isJSON(String plainJson) {
        Matcher m = JSON_TYPE.matcher(plainJson);
        if (m.lookingAt()) {
            try {
                JsonUtil.prettyJSON(plainJson, false);
                return true;
            }
            catch (IOException e) {
                return false;
            }       
        }
        else {
            return false;
        }       
    }

    public static String prettyXML(String plainXML) throws IOException {
        return prettyXML(plainXML, true);
    }
    
    public static String prettyXML(String plainXML, boolean pretty) throws IOException {
        StringWriter sw = new StringWriter();
        Transformer transformer;
        try {
            DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
            Document document = docBuilder.parse(new InputSource(new StringReader(plainXML)));
            transformer = TransformerFactory.newInstance()
                    .newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, pretty ? "yes" : "no");
            transformer.transform(new DOMSource(document),
                                  new StreamResult(sw));
        } catch (TransformerConfigurationException ex) {
            throw new IOException(ex);
        } catch (ParserConfigurationException ex) {
            throw new IOException(ex);
        } catch (SAXException ex) {
            throw new IOException(ex);
        } catch (TransformerException ex) {
            throw new IOException(ex);
        }
        return sw.toString();
    }
    
    public static String prettyJSON(String plainJson) throws IOException {
        return JsonUtil.prettyJSON(plainJson, true);
    }
    
    
}
