Burp suite 拡張 YaguraExtender
=============

Language/[English](Readme.md)

このツールは、PortSwigger社の製品であるBurp Suiteの拡張になります。

Burp Suiteにはアジアの文字エンコーディングの利用に欠点があります。

このツールは、主に日本のユーザーを対象とした拡張機能です。
また、中国語と韓国語のエンコードもサポートしていますが、完全にはテストされておらず、問題が含まれている場合があります。

## ヘルプ
利用方法等の詳細なヘルプは、help ディレクトリの help.html を参照してください。

オンラインの場合は、[help](/src/main/help/help-ja.adoc)を参照して下さい。

## ビルド

```
gradlew build
```

## 必須ライブラリ
* BurpExtlib v2.1.0.0 [BurpExtLib](https://github.com/raise-isayan/BurpExtLib)

## 動作環境

### Java
* JRE(JDK) 11 (Open JDK を推奨)(https://openjdk.java.net/)

### Burp suite
* v2020以上 (http://www.portswigger.net/burp/)

### 開発環境
* NetBean 12.2 (https://netbeans.apache.org/)
* Gradle 6.8.1 (https://gradle.org/)
* asciidoc (http://asciidoc.org/) 

### 利用ライブラリ

* Apache common codec (https://commons.apache.org/proper/commons-codec/)
  * Apache License 2.0
  * http://www.apache.org/licenses/

* RSyntaxTextArea (http://bobbylight.github.io/RSyntaxTextArea/)
  * BSD 3-Clause license
  * https://github.com/bobbylight/RSyntaxTextArea/blob/master/RSyntaxTextArea/src/main/resources/META-INF/LICENSE

* gson (https://github.com/google/gson)
  * Apache License 2.0
  * https://github.com/google/gson/blob/master/LICENSE

* Universal Chardet for java (https://code.google.com/archive/p/juniversalchardet/)
  * MPL 1.1
  * https://code.google.com/archive/p/juniversalchardet/

* Use Icon (http://www.famfamfam.com/lab/icons/silk/)
  * Creative Commons Attribution 2.5 License
  * http://www.famfamfam.com/lab/icons/silk/

## 注意事項
このツールは、私個人が勝手に開発したもので、PortSwigger社は一切関係ありません。本ツールを使用したことによる不具合等についてPortSwiggerに問い合わせないようお願いします。

