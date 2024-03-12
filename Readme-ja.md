Burp suite 拡張 YaguraExtender
=============

Language/[English](Readme.md)

このツールは、PortSwigger社の製品であるBurp Suiteの拡張になります。

Burp Suiteにはアジアの文字エンコーディングの利用に欠点があります。

このツールは、主に日本のユーザーを対象とした拡張機能です。
また、中国語と韓国語のエンコードもサポートしていますが、完全にはテストされておらず、問題が含まれている場合があります。

## 最新版について

メインのリポジトリ(master)には開発中のコードが含まれている場合があります。
安定したリリース版は､以下よりダウンロードしてください。

* https://github.com/raise-isayan/YaguraExtender/releases

利用するバージョンは以下のものをご利用ください

* Burp suite v2023.1.2 より前のバージョン
   * YagraExtender v2.2.14.0 以前

* Burp suite v2023.1.2 より後のバージョン
   * YagraExtender v3.0.0 以降(ベータ版)
   * YagraExtension v2.2.14.0 以前(現時点で利用可)

## ヘルプ
利用方法等の詳細なヘルプは、help ディレクトリの help.html を参照してください。

オンラインの場合は、[help](/src/main/help/help-ja.adoc)を参照して下さい。

## ビルド

```
gradlew release
```

## 動作環境

### Java
* JRE(JDK) 17 (Open JDK を推奨)(https://openjdk.java.net/)

### Burp suite
* v2023.1.2以上 (http://www.portswigger.net/burp/)

### 開発環境
* NetBeans 20 (https://netbeans.apache.org/)
* Gradle 7.6 (https://gradle.org/)
* asciidoc (http://asciidoc.org/)

## 必須ライブラリ
ビルドには別途 [BurpExtensionCommons](https://github.com/raise-isayan/BurpExtensionCommons) のライブラリを必要とします。
* BurpExtensionCommons v3.0.x

### 利用ライブラリ

* Apache common codec (https://commons.apache.org/proper/commons-codec/)
  * Apache License 2.0
  * http://www.apache.org/licenses/

* RSyntaxTextArea (http://bobbylight.github.io/RSyntaxTextArea/)
  * BSD 3-Clause license
  * https://github.com/bobbylight/RSyntaxTextArea/blob/master/RSyntaxTextArea/src/main/resources/META-INF/LICENSE

* Google gson (https://github.com/google/gson)
  * Apache License 2.0
  * https://github.com/google/gson/blob/master/LICENSE

* okHttp/MockServer (https://github.com/square/okhttp)
  * Apache License 2.0
  * https://github.com/square/okhttp/blob/master/LICENSE.txt

* okhttp-digest (https://github.com/rburgst/okhttp-digest)
  * Apache License 2.0
  * https://github.com/rburgst/okhttp-digest/blob/master/LICENSE.md

* Universal Chardet for java (https://code.google.com/archive/p/juniversalchardet/)
  * MPL 1.1
  * https://code.google.com/archive/p/juniversalchardet/

* Use Icon (http://www.famfamfam.com/lab/icons/silk/)
  * Creative Commons Attribution 2.5 License
  * http://www.famfamfam.com/lab/icons/silk/

## 注意事項
このツールは、私個人が勝手に開発したもので、PortSwigger社は一切関係ありません。本ツールを使用したことによる不具合等についてPortSwiggerに問い合わせないようお願いします。

