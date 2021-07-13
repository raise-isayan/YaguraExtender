Burp suite Extension YaguraExtender
=============

Language/[Japanese](Readme-ja.md)

This tool is an extension of Burp Suite, a product of PortSwigger.

Burp Suite has drawbacks when using Asian character encodings.
This tool is an extension mainly targeting Japanese users.
It also supports Chinese and Korean encodings, but may not be fully tested and may contain issues.

## help

Please refer to help.html in help directory for detailed help such as how to use.

If you are online, please refer to [help](/src/main/help/help.adoc).

## build

```
gradlew release
```

## Operating environment

### Java
* JRE (JDK) 11 (Open JDK is recommended) (https://openjdk.java.net/)

### Burp suite
* v2020 or higher (http://www.portswigger.net/burp/)

### Development environment
* NetBean 12.4 (https://netbeans.apache.org/)
* Gradle 7.0.2 (https://gradle.org/)
* asciidoc (http://asciidoc.org/) 

## Required library
Building requires a [BurpExtensionCommons](https://github.com/raise-isayan/BurpExtensionCommons) library.
* BurpExtensionCommons v0.4.x

## Use Library
* Apache common codec (https://commons.apache.org/proper/commons-codec/)
  * Apache License 2.0
  * http://www.apache.org/licenses/

* RSyntaxTextArea (http://bobbylight.github.io/RSyntaxTextArea/)
  * BSD 3-Clause license
  * https://github.com/bobbylight/RSyntaxTextArea/blob/master/RSyntaxTextArea/src/main/resources/META-INF/LICENSE

* Google gson (https://github.com/google/gson)
  * Apache License 2.0
  * https://github.com/google/gson/blob/master/LICENSE

* Universal Chardet for java (https://code.google.com/archive/p/juniversalchardet/)
  * MPL 1.1
  * https://code.google.com/archive/p/juniversalchardet/

* Use Icon (http://www.famfamfam.com/lab/icons/silk/)
  * Creative Commons Attribution 2.5 License
  * http://www.famfamfam.com/lab/icons/silk/

## Notes
This tool was developed by myself and has nothing to do with PortSwigger. Please do not contact PortSwigger for any problems caused by using this tool.

