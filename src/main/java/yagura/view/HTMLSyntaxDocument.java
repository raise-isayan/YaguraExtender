package yagura.view;

import java.util.HashSet;
import javax.swing.text.PlainDocument;

/**
 *
 * @author isayan
 */
public class HTMLSyntaxDocument extends AbstractSyntaxDocument {

    private final static String KEYWORDS[] = {
        "_blank",
        "_parent",
        "_self",
        "_top",
        "a",
        "abbr",
        "above",
        "absbottom",
        "absmiddle",
        "accesskey",
        "acronym",
        "action",
        "address",
        "align",
        "all",
        "applet",
        "area",
        "autoplay",
        "autostart",
        "b",
        "background",
        "base",
        "basefont",
        "baseline",
        "behavior",
        "below",
        "bgcolor",
        "bgsound",
        "big",
        "blink",
        "blockquote",
        "body",
        "border",
        "bordercolor",
        "bordercolordark",
        "bordercolorlight",
        "bottom",
        "box",
        "br",
        "button",
        "caption",
        "cellpadding",
        "cellspacing",
        "center",
        "challenge",
        "char",
        "checkbox",
        "checked",
        "cite",
        "class",
        "clear",
        "clip",
        "code",
        "codebase",
        "codetype",
        "col",
        "colgroup",
        "color",
        "cols",
        "colspan",
        "comment",
        "controls",
        "data",
        "dd",
        "declare",
        "defer",
        "del",
        "delay",
        "dfn",
        "dir",
        "direction",
        "disabled",
        "div",
        "dl",
        "doctype",
        "dt",
        "em",
        "embed",
        "enctype",
        "face",
        "fieldset",
        "file",
        "font",
        "for",
        "form",
        "frame",
        "frameborder",
        "frameset",
        "get",
        "groups",
        "groups",
        "gutter",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "h7",
        "head",
        "height",
        "hidden",
        "hn",
        "hr",
        "href",
        "hsides",
        "hspace",
        "html",
        "i",
        "id",
        "iframe",
        "ilayer",
        "image",
        "img",
        "index",
        "inherit",
        "input",
        "ins",
        "isindex",
        "javascript",
        "justify",
        "kbd",
        "keygen",
        "label",
        "language",
        "layer",
        "left",
        "legend",
        "lhs",
        "li",
        "link",
        "listing",
        "loop",
        "map",
        "marquee",
        "maxlength",
        "menu",
        "meta",
        "method",
        "methods",
        "middle",
        "multicol",
        "multiple",
        "name",
        "next",
        "nextid",
        "nobr",
        "noembed",
        "noframes",
        "nolayer",
        "none",
        "nosave",
        "noscript",
        "notab",
        "nowrap",
        "object",
        "ol",
        "onblur",
        "onchange",
        "onclick",
        "onfocus",
        "onload",
        "onmouseout",
        "onmouseover",
        "onreset",
        "onselect",
        "onsubmit",
        "option",
        "p",
        "pagex",
        "pagey",
        "palette",
        "panel",
        "param",
        "parent",
        "password",
        "plaintext",
        "pluginspage",
        "post",
        "pre",
        "previous",
        "q",
        "radio",
        "rel",
        "repeat",
        "reset",
        "rev",
        "rhs",
        "right",
        "rows",
        "rowspan",
        "rules",
        "s",
        "samp",
        "save",
        "script",
        "scrollamount",
        "scrolldelay",
        "select",
        "selected",
        "server",
        "shapes",
        "show",
        "size",
        "small",
        "song",
        "spacer",
        "span",
        "src",
        "standby",
        "strike",
        "strong",
        "style",
        "sub",
        "submit",
        "summary",
        "sup",
        "tabindex",
        "table",
        "target",
        "tbody",
        "td",
        "text",
        "textarea",
        "textbottom",
        "textfocus",
        "textmiddle",
        "texttop",
        "tfoot",
        "th",
        "thead",
        "title",
        "top",
        "tr",
        "tt",
        "txtcolor",
        "type",
        "u",
        "ul",
        "urn",
        "usemap",
        "valign",
        "value",
        "valuetype",
        "var",
        "visibility",
        "void",
        "vsides",
        "vspace",
        "wbr",
        "width",
        "wrap",
        "xmp"};
    
    @Override
    public HashSet<String> getKeywords() {
        final HashSet<String> keywords = new HashSet<>();
        for (String kw : KEYWORDS) {
            keywords.add(kw);
        }
        return keywords;
    }

    @Override
    protected boolean isDelimiter(String character) {
        String operands = ";:{}()[]+-/%<=>!&|^~*";

        if (Character.isWhitespace(character.charAt(0))
                || operands.contains(character)) {
            return true;
        } else {
            return false;
        }
    }

    @Override
    protected boolean isQuoteDelimiter(String character) {
        String quoteDelimiters = "\"'";
        return quoteDelimiters.contains(character);
    }

    @Override
    protected String getStartDelimiter() {
        return "<!--";
    }

    @Override
    protected String getEndDelimiter() {
        return "-->";
    }

    @Override
    protected String getSingleLineDelimiter() {
        return null;
    }

    @Override
    protected String getEscapeString(String quoteDelimiter) {
        return "\\" + quoteDelimiter;
    }

}
