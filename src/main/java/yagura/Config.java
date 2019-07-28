package yagura;

import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import javax.xml.bind.JAXB;
import yagura.model.OptionProperty;

/**
 *
 * @author isayan
 */
public class Config {

    public static void saveToXML(File fi, OptionProperty option) throws IOException {
        JAXB.marshal(option, fi);
    }

    public static void loadFromXML(File fi, OptionProperty option) throws IOException {
        OptionProperty property = JAXB.unmarshal(fi, OptionProperty.class);
        option.setProperty(property);
    }

    /**
     * Propertyファイルの読み込み
     *
     * @param content コンテンツ内容
     * @param option 設定オプション
     * @throws java.io.IOException
     */
    public static void loadFromXml(String content, OptionProperty option) throws IOException {
        OptionProperty property = JAXB.unmarshal(content, OptionProperty.class);
        option.setProperty(property);
    }

    public static String saveToXML(OptionProperty option) throws IOException {
        StringWriter writer = new StringWriter();
        JAXB.marshal(option, writer);
        return writer.toString();
    }

}
