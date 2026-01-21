package yagura.dynamic;

import java.io.File;
import java.io.FileFilter;
import java.io.FileNotFoundException;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

/**
 *
 * @author isayan
 */
public class BambdaFile {

    private final static String KEY_ID = "id";
    private final static String KEY_NAME = "name";
    private final static String KEY_FUNCTION = "function";
    private final static String KEY_LOCATION = "location";
    private final static String KEY_SOURCE = "source";
    private final static String KEY_CONTENTS = "source_contents";

    private final static String SOURCE_ML_SEP = "|-";

    public BambdaFile() {

    }

    private final static FileFilter BAMBDA_FILTER = new FileFilter() {
        @Override
        public boolean accept(File pathname) {
            return pathname.getName().endsWith(".bambda");
        }
    };

    public static File[] bambdaFiles(File file) {
        return file.listFiles(BAMBDA_FILTER);
    }

    private final Map<String, String> token = new HashMap<>();

    public void parse(File file) throws FileNotFoundException {
        try (Scanner scanner = new Scanner(file)) {
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                if (line.isEmpty()) {
                    continue;
                }
                String[] parts = line.split(":", 2);
                if (parts.length == 2) {
                    String key = parts[0].trim();
                    String value = parts[1].trim();
                    token.put(key, value);
                    if (KEY_SOURCE.equals(key) && SOURCE_ML_SEP.equals(value)) {
                        StringBuffer content = new StringBuffer();
                        while (scanner.hasNextLine()) {
                            String last = scanner.nextLine();
                            content.append(last.stripLeading());
                            content.append("\n");
                        }
                        token.put(KEY_CONTENTS, content.toString());
                    }
                }
            }
        }
    }

    public String getID() {
        return this.token.get(KEY_ID);
    }

    public String getName() {
        return this.token.get(KEY_NAME);
    }

    public String getFunction() {
        return this.token.get(KEY_FUNCTION);
    }

    public String getLocation() {
        return this.token.get(KEY_LOCATION);
    }

    public boolean isMultiline() {
        String source = this.token.get(KEY_SOURCE);
        return (source != null) && SOURCE_ML_SEP.equals(source);
    }

    public String getSource() {
        return this.token.get(KEY_SOURCE);
    }

    public String getSourceContents() {
        if (isMultiline()) {
            return this.token.get(KEY_CONTENTS);
        } else {
            return this.token.get(KEY_SOURCE);
        }
    }

}
