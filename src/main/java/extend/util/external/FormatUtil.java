package extend.util.external;

import extension.helpers.json.JsonUtil;
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
    private final static Pattern XML_TYPE = Pattern.compile("^[\\s\r\n]*((<!(.*?)>)|(<\\?(.*?)\\?>)|(<\\w+>)|(<!--(.*?)-->}))", Pattern.DOTALL);

    public static boolean isUrl(String plainURL) {
        Matcher m = URL_TYPE.matcher(plainURL);
        return m.find();
    }

    public static boolean isXml(String xmlString) {
        Matcher m = XML_TYPE.matcher(xmlString);
        if (m.lookingAt()) {
            return validXml(xmlString);
        }        
        return false;
    }

    public static boolean validXml(String xmlString) {
        StringWriter sw = new StringWriter();
        try {
            DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
            Document document = docBuilder.parse(new InputSource(new StringReader(xmlString)));
        } catch (ParserConfigurationException | SAXException | IOException ex) {
            return false;
        }
        return true;
    }
    
    public static boolean isJson(String jsonString) {
        return JsonUtil.isJson(jsonString);
    }

    public static boolean isJsonp(String jsonString) {
        return JsonUtil.isJsonp(jsonString);
    }
        
    public static String prettyXml(String xmlString) throws IOException {
        return prettyXml(xmlString, true);
    }

    public static String prettyXml(String xmlString, boolean pretty) throws IOException {
        StringWriter sw = new StringWriter();
        Transformer transformer;
        try {
            DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
            Document document = docBuilder.parse(new InputSource(new StringReader(xmlString)));
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

    public static String prettyJson(String jsonString) throws IOException {
        return JsonUtil.prettyJson(jsonString, true);
    }

    public static String prettyJson(String jsonString, boolean pretty) throws IOException {
        return JsonUtil.prettyJson(jsonString, pretty);
    }
        
}
