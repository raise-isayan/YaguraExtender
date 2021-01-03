package aspx.viewstate;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import extend.util.Util;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author isayan
 */
public class ViewStateParser {
    private final static boolean DEBUG_MODE = false;
        
    // Optimized type tokens
    private final static byte Token_Int16 = 0x01;
    private final static byte Token_Int32 = 0x02;
    private final static byte Token_Byte = 0x03;
    private final static byte Token_Char = 0x04;
    private final static byte Token_String = 0x05;
    private final static byte Token_DateTime = 0x06;
    private final static byte Token_Double = 0x07;
    private final static byte Token_Single = 0x08;
    private final static byte Token_Color = 0x09;
    private final static byte Token_KnownColor = 0x0a;
    private final static byte Token_IntEnum = 0x0b;
    private final static byte Token_EmptyColor = 0x0c;
    private final static byte Token_Pair = 0x0f;
    private final static byte Token_Triplet = 0x10;
    private final static byte Token_Array = 0x14;
    private final static byte Token_StringArray = 0x15;
    private final static byte Token_ArrayList = 0x16;
    private final static byte Token_Hashtable = 0x17;
    private final static byte Token_HybridDictionary = 0x18;
    private final static byte Token_Type = 0x19;

    private final static byte Token_Unit = 0x1b;
    private final static byte Token_EmptyUnit = 0x1c;
    private final static byte Token_EventValidationStore = 0x1d;

    // String-table optimized strings
    private final static byte Token_IndexedStringAdd = 0x1e;
    private final static byte Token_IndexedString = 0x1f;

    // Semi-optimized (TypeConverter-based)
    private final static byte Token_StringFormatted = 0x28;

    // Semi-optimized (Types)
    private final static byte Token_TypeRefAdd = 0x29;
    private final static byte Token_TypeRefAddLocal = 0x2a;
    private final static byte Token_TypeRef = 0x2b;

    // Un-optimized (Binary serialized) types
    private final static byte Token_BinarySerialized = 0x32;

    // Optimized for sparse arrays
    private final static byte Token_SparseArray = 0x3c;

    // Constant values
    private final static byte Token_Null = 0x64;
    private final static byte Token_EmptyString = 0x65;
    private final static byte Token_ZeroInt32 = 0x66;
    private final static byte Token_True = 0x67;
    private final static byte Token_False = 0x68;

    // Format and Version
    private final static byte Marker_Format = (byte) 0xFF;
    private final static byte Marker_Version_1 = 0x01;

//    private static enum Token {
//        // Optimized type tokens
//        Token_Int16(0x01),
//        Token_Int32(0x02),
//        Token_Byte(0x03),
//        Token_Char(0x04),
//        Token_String(0x05),
//        Token_DateTime(0x06),
//        Token_Double(0x07),
//        Token_Single(0x08),
//        Token_Color(0x09),
//        Token_KnownColor(0x0a),
//        Token_IntEnum(0x0b),
//        Token_EmptyColor(0x0c),
//        Token_Pair(0x0f),
//        Token_Triplet(0x10),
//        Token_Array(0x14),
//        Token_StringArray(0x15),
//        Token_ArrayList(0x16),
//        Token_Hashtable(0x17),
//        Token_HybridDictionary(0x18),
//        Token_Type(0x19),
//        Token_Unit(0x1b),
//        Token_EmptyUnit(0x1c),
//        Token_EventValidationStore(0x1d),
//        // String-table optimized strings
//        Token_IndexedStringAdd(0x1e),
//        Token_IndexedString(0x1f),
//        // Semi-optimized (TypeConverter-based)
//        Token_StringFormatted(0x28),
//        // Semi-optimized (Types)
//        Token_TypeRefAdd(0x29),
//        Token_TypeRefAddLocal(0x2a),
//        Token_TypeRef(0x2b),
//        // Un-optimized (Binary serialized) types
//        Token_BinarySerialized(0x32),
//        // Optimized for sparse arrays
//        Token_SparseArray(0x3c),
//        // Constant values
//        Token_Null(0x64),
//        Token_EmptyString(0x65),
//        Token_ZeroInt32(0x66),
//        Token_True(0x67),
//        Token_False(0x68);
//
//        private final int id;
//
//        Token(int id) {
//            this.id = id;
//        }
//
//        public byte getTokenId() {
//            return (byte)this.id;
//        }
//
//    }
        
    private boolean detail = false;

    public boolean getDetailMode() {
        return detail;
    }

    public void setDetailMode(boolean detail) {
        this.detail = detail;
    }

    public ViewState parse(String viewStateEncode) {
        ByteBuffer decodeBuffer = ByteBuffer.wrap(Base64.getDecoder().decode(viewStateEncode));
        byte formatMarker = decodeBuffer.get();
        if (formatMarker == Marker_Format) {
            byte versionMarker = decodeBuffer.get();
            if (versionMarker == Marker_Version_1) {
                JsonElement jsonRoot = decodeJsonObject(decodeBuffer);
                // hmac
                int hmac_len = decodeBuffer.remaining();
                if (hmac_len > 0) {
                    byte[] hmac = new byte[hmac_len];
                    decodeBuffer.get(hmac);
                    ViewState viewState = new ViewState(jsonRoot, hmac);
                    return viewState;
                } else {
                    ViewState viewState = new ViewState(jsonRoot);
                    return viewState;
                }
            }
            else {
                ViewState viewState = new ViewState();
                return viewState;        
            }
        }
        else {
            ViewState viewState = new ViewState();
            return viewState;        
        }
    }
    
    public JsonElement decodeJsonObject(ByteBuffer bbf) {
        JsonElement decodeNode = JsonNull.INSTANCE;
        byte token = bbf.get();
if (DEBUG_MODE) System.out.println(String.format("Type:0x%02x", token));
        try {
            switch (token) {
                case Token_Int16: { //?
if (DEBUG_MODE) System.out.println("Token_Int16");
                    short value = bbf.getShort();
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("Int16", value);
                    decodeNode = jsonNode;
                    break;
                }
                case Token_Int32: { //?
if (DEBUG_MODE) System.out.println("Token_Int32");
                    int value = readEncodedInt32(bbf);
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("Int32", value);
                    decodeNode = jsonNode;
                    break;
                }
                case Token_Byte: { //
                    byte value = bbf.get();
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("byte", value);
                    decodeNode = jsonNode;
                    break;
                }
                case Token_Char: { //??
if (DEBUG_MODE) System.out.println("Token_Char");
                    // 2byteのケースが存在                    
                    //char value = bbf.getChar();
                    byte value = bbf.get();
if (DEBUG_MODE) System.out.println(String.format("\tchar:%c, \\u%04x", value, (int)value));
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("Char", value);
                    decodeNode = jsonNode;
                    break;
                }
                case Token_String: { //?
                    String value = readString(bbf);
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("String", value);
                    decodeNode = jsonNode;
                    break;
                }
                case Token_DateTime: { //?
                    long value = bbf.getLong();
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("DateTime", value);
                    decodeNode = jsonNode;
                    break;
                }
                case Token_Double: { //?
                    double value = bbf.getDouble();
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("Double", value);
                    decodeNode = jsonNode;
                    break;
                }
                case Token_Single: { //?
                    float value = bbf.getFloat();
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("Single", value);
                    decodeNode = jsonNode;
                    break;
                }
                case Token_Color: { //?
                    int value = bbf.getShort() & 0xffffffff;
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("Color", value);
                    decodeNode = jsonNode;
                    break;                
                }
                case Token_KnownColor: { //?
                    int value = readEncodedInt32(bbf) & 0xffffffff;
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("KnownColor", value);
                    decodeNode = jsonNode;
                    break;
                }
                case Token_IntEnum: { //?
                    String enumType = readTypeIdent(bbf);
                    int enumValue = readEncodedInt32(bbf);
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("Type", enumType);
                    jsonNode.addProperty("Value", enumValue);
                    JsonObject jsonEnum = new JsonObject();
                    jsonEnum.add("IntEnum", jsonNode);
                    decodeNode = jsonEnum;
                    break;
                }
                case Token_EmptyColor: { //
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.add("Color", JsonNull.INSTANCE);
                    decodeNode = jsonNode;
                    break;
                }
                case Token_Pair: { //?
if (DEBUG_MODE) System.out.println("Token_Pair");
                    JsonElement jsonNode = JsonNull.INSTANCE;
                    if (detail) {
                        JsonObject jsonPairObject = new JsonObject();
                        JsonElement jsonPairFirst = decodeJsonObject(bbf);
                        if (!JsonNull.INSTANCE.equals(jsonPairFirst)) {
                            jsonPairObject.add("First", jsonPairFirst);

                        }
                        JsonElement jsonPairSecond = decodeJsonObject(bbf);
                        if (!JsonNull.INSTANCE.equals(jsonPairSecond)) {
                            jsonPairObject.add("Second", jsonPairSecond);
                        }
                        JsonObject jsonPair = new JsonObject();
                        jsonPair.add("Pair", jsonPairObject);
                        jsonNode = jsonPair;
                    } else {
                        JsonArray jsonPairArray = new JsonArray();
                        jsonPairArray.add(decodeJsonObject(bbf));
                        jsonPairArray.add(decodeJsonObject(bbf));
                        JsonObject jsonPair = new JsonObject();
                        jsonPair.add("Pair", jsonPairArray);
                        jsonNode = jsonPair;
                    }
                    decodeNode = jsonNode;
                    break;
                }
                case Token_Triplet: { //?
if (DEBUG_MODE) System.out.println("Token_Triplet");
                    JsonElement jsonNode = JsonNull.INSTANCE;
                    if (detail) {
                        JsonObject jsonTripletObject = new JsonObject();
                        JsonElement jsonTripletFirst = decodeJsonObject(bbf);
                        if (!JsonNull.INSTANCE.equals(jsonTripletFirst)) {
                            jsonTripletObject.add("First", jsonTripletFirst);
                        }
                        JsonElement jsonTripletSecond = decodeJsonObject(bbf);
                        if (!JsonNull.INSTANCE.equals(jsonTripletSecond)) {
                            jsonTripletObject.add("Second", jsonTripletSecond);
                        }
                        JsonElement jsonTripletThird = decodeJsonObject(bbf);
                        if (!JsonNull.INSTANCE.equals(jsonTripletThird)) {
                            jsonTripletObject.add("Third", jsonTripletThird);
                        }
                        JsonObject jsonTriplet = new JsonObject();
                        jsonTriplet.add("Triplet", jsonTripletObject);
                        jsonNode = jsonTriplet;
                    } else {
                        JsonArray jsonTripletArray = new JsonArray();
                        JsonElement jsonTripletFirst = decodeJsonObject(bbf);
                        jsonTripletArray.add(jsonTripletFirst);
                        JsonElement jsonTripletSecond = decodeJsonObject(bbf);
                        jsonTripletArray.add(jsonTripletSecond);
                        JsonElement jsonTripletThird = decodeJsonObject(bbf);
                        jsonTripletArray.add(jsonTripletThird);
                        JsonObject jsonTriplet = new JsonObject();
                        jsonTriplet.add("Triplet", jsonTripletArray);
                        jsonNode = jsonTriplet;
                    }
                    decodeNode = jsonNode;
                    break;
                }
                case Token_Array: {
                    String enumType = readTypeIdent(bbf);
                    int count = readEncodedInt32(bbf);
if (DEBUG_MODE) System.out.println("Token_Array.type:" + enumType);
if (DEBUG_MODE) System.out.println("Token_Array.count:" + count);
                    JsonArray jsonArray = new JsonArray();
                    for (int i = 0; i < count; i++) {
                        jsonArray.add(decodeJsonObject(bbf));
                    }
                    JsonObject jsonList = new JsonObject();
                    jsonList.add("Array" + " " + enumType, jsonArray);
                    decodeNode = jsonList;
                    break;
                }
                case Token_StringArray: {
                    int count = readEncodedInt32(bbf);
if (DEBUG_MODE) System.out.println("Token_StringArray.count:" + count);
                    JsonArray jsonArray = new JsonArray();
                    String[] array = new String[count];
                    for (int i = 0; i < count; i++) {
                        jsonArray.add(readString(bbf));
                    }
                    JsonObject jsonList = new JsonObject();
                    jsonList.add("StringArray", jsonArray);
                    decodeNode = jsonList;
                    break;
                }
                case Token_ArrayList: { //?
                    int count = readEncodedInt32(bbf);
if (DEBUG_MODE) System.out.println("Token_ArrayList.count:" + count);
                    JsonArray jsonArray = new JsonArray();
                    for (int i = 0; i < count; i++) {
                        jsonArray.add(decodeJsonObject(bbf));
                    }
                    JsonObject jsonList = new JsonObject();
                    jsonList.add("ArrayList", jsonArray);
                    decodeNode = jsonList;
                    break;
                }
                case Token_Hashtable:
                case Token_HybridDictionary: {
                    int count = readEncodedInt32(bbf);
if (DEBUG_MODE) System.out.println("Token_Hashtable.count:" + count);
                    JsonArray jsonArray = new JsonArray();
                    for (int i = 0; i < count; i++) {
                        JsonObject jsonMap = new JsonObject();
                        jsonMap.add("Key", decodeJsonObject(bbf));
                        jsonMap.add("Value", decodeJsonObject(bbf));
                        jsonArray.add(jsonMap);
                    }
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.add("Hashtable", jsonArray);
                    decodeNode = jsonNode;
                    break;
                }
                case Token_Type: {
                    decodeNode = readType(bbf);
                    break;
                }
                case Token_Unit: {
                    JsonObject jsonUnit = new JsonObject();
                    jsonUnit.addProperty("UnitType", bbf.getInt());
                    jsonUnit.addProperty("Value", bbf.getDouble());
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.add("Unit", jsonUnit);
                    decodeNode = jsonNode;
                    break;
                }
                case Token_EmptyUnit: {
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.add("Unit", JsonNull.INSTANCE);
                    decodeNode = jsonNode;
                    break;
                }
                case Token_EventValidationStore: {
                    // not implements                                                
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("NotImplements", "EventValidationStore");
                    decodeNode = jsonNode;
                    break;
                }
                case Token_IndexedStringAdd: // 
                case Token_IndexedString: {  //?
                    JsonObject jsonNode = new JsonObject();
                    String value = readIndexedString(bbf, token);
if (DEBUG_MODE) System.out.println("\tindexString:" + value);
                    jsonNode.addProperty("IndexedString", value);
                    decodeNode = jsonNode;
                    break;
                }
                case Token_StringFormatted: {
                    // not implements                                
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("NotImplements", "StringFormatted");
                    decodeNode = jsonNode;
                    break;
                }
                case Token_BinarySerialized: {
                    int count = readEncodedInt32(bbf);
if (DEBUG_MODE) System.out.println("Token_BinarySerialized.count:" + count);
                    byte[] array = new byte[count];
                    bbf.get(array);
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("object", new String(array, StandardCharsets.UTF_8));
                    decodeNode = jsonNode;
                    break;
                }
                case Token_SparseArray: {
                    String elementType = readTypeIdent(bbf);
                    int count = readEncodedInt32(bbf);
                    int itemCount = readEncodedInt32(bbf);
                    if (itemCount > count) {
                        throw new IllegalArgumentException("Invalid Serialized Data");
                    }
if (DEBUG_MODE) System.out.println("Token_SparseArray.type:" + elementType);
if (DEBUG_MODE) System.out.println("Token_SparseArray.count:" + count);
if (DEBUG_MODE) System.out.println("Token_SparseArray.itemCount:" + itemCount);
                    ArrayList<JsonElement> list = new ArrayList<>();
                    for (int i = 0; i < count; i++) {
                        list.add(JsonNull.INSTANCE);
                    }                        
                    for (int i = 0; i < itemCount; i++) {
                        int nextPos = readEncodedInt32(bbf);
                        if (nextPos >= count || nextPos < 0) {
                            throw new IllegalArgumentException("Invalid Serialized Data:" + nextPos);
                        }
                        list.set(nextPos, decodeJsonObject(bbf));
                    }
                    JsonArray jsonArray = new JsonArray();
                    for (int i = 0; i < list.size(); i++) {
                        jsonArray.add(list.get(i));
                    }                    
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.add("SparseArray" + " " + elementType + "[]", jsonArray);
                    decodeNode = jsonNode;
                    break;
                }
                case Token_Null: { //
                    JsonElement jsonNode = JsonNull.INSTANCE;
                    decodeNode = jsonNode;
                    break;
                }
                case Token_EmptyString: { //
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("String", "");
                    decodeNode = jsonNode;
                    break;
                }
                case Token_ZeroInt32: { //
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("Int32", 0);
                    decodeNode = jsonNode;
                    break;
                }
                case Token_True: { //
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("bool", true);
                    decodeNode = jsonNode;
                    break;
                }
                case Token_False: { //
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("bool", false);
                    decodeNode = jsonNode;
                    break;
                }
                default: {
if (DEBUG_MODE) System.out.println("Unknown token:" + String.format("0x%02x len=%d", token, bbf.remaining()));
                    JsonObject jsonNode = new JsonObject();
                    jsonNode.addProperty("Unknown token", String.format("0x%02x", token));
                    decodeNode = jsonNode;
                    break;
                }
            }
            return decodeNode;
        } catch (RuntimeException ex) {
if (DEBUG_MODE) System.out.println(ex.getMessage() + ":" + Util.getStackTrace(ex));
        }
        return decodeNode;
    }

//    private int readInt16(java.io.InputStream istm) throws IOException {
//        int value = 0;
//        byte [] buff = new byte[2]; 
//        if (2 != istm.read(buff)) {
//            value = (buff[0] | buff[1] << 8);
//        }
//        return value;
//    }
    private int readEncodedInt32(ByteBuffer bbf) {
        int value = 0;
        int shift = 0;
        byte readByte = 0;
        do {
            if (shift == 5 * 7) // 5 bytes max per Int32, shift += 7
            {
                throw new IllegalArgumentException("Illegal Format 7BitInt32");
            }
            readByte = bbf.get();
            value |= (readByte & 0x7F) << shift;
            shift += 7;
        } while ((readByte & 0x80) != 0);
        return value;
    }

    public String readString(ByteBuffer bbf) {
        StringBuilder sb = new StringBuilder();
        int currPos = 0;
        int stringLength = readEncodedInt32(bbf);
        if (stringLength < 0) {
            throw new IllegalArgumentException("Invalid String Length");
        }
        // isEmpty
        if (stringLength == 0) {
            return "";
        }

        byte[] byteBuff = new byte[256];
        int readLength = ((stringLength - currPos) > byteBuff.length) ? byteBuff.length : (stringLength - currPos);
        ByteBuffer b = bbf.get(byteBuff, 0, readLength);
        sb.append(new String(byteBuff, 0, readLength));
        return sb.toString();
    }

    private String readIndexedString(ByteBuffer bbf, byte token) {
        String value = "";
        switch (token) {
            case Token_IndexedString: {
                byte tableIndex = bbf.get();
                value = new String("StringReference:" + tableIndex);
                break;
            }
            default: {
                value = readString(bbf);
                break;
            }
        }
        return value;
    }

    private JsonObject readType(ByteBuffer bbf) {
        final String[] KnownTypes = new String[]{"Object", "int", "String", "bool"};
        JsonObject decodeNode = new JsonObject();
        byte token = bbf.get();
        switch (token) {
            case Token_TypeRef: {
                int typeID = readEncodedInt32(bbf);
                JsonObject jsonType = new JsonObject();
                if (typeID < KnownTypes.length) {
                    jsonType.addProperty("Type", KnownTypes[typeID]);
                } else {
                    jsonType.addProperty("Type", "Enum");
                }
                decodeNode = jsonType;
                break;
            }
            case Token_TypeRefAddLocal:
            case Token_TypeRefAdd: {
                String typeName = readString(bbf);
                JsonObject jsonType = new JsonObject();
                jsonType.addProperty("TypeRef", typeName);
                decodeNode = jsonType;
                break;
            }
            default: {
                break;
            }
        }
        return decodeNode;
    }

    private String readTypeIdent(ByteBuffer bbf) {
        JsonObject ident = readType(bbf);
        if (ident.has("Type")) {
            return ident.get("Type").getAsString();
        } else if (ident.has("TypeRef")) {
            return ident.get("TypeRef").getAsString();
        }
        return "Unknown";
    }

    private final static Pattern PTN_URL = Pattern.compile("%([0-9a-fA-F]{2})");

    public static boolean isUrlencoded(String value) {
        Matcher m = PTN_URL.matcher(value);
        return m.find();
    }

    public static String prettyJson(JsonElement jsonElement, boolean pretty) {
        if (pretty) {
            Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().serializeNulls().create();
            return gson.toJson(jsonElement);
        } else {
            Gson gson = new GsonBuilder().disableHtmlEscaping().serializeNulls().create();
            return gson.toJson(jsonElement);
        }
    }

}
