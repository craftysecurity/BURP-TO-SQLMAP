BURP-SQLMAP is an extension for Burp Suite that generates sqlmap commands directly from HTTP requests by parsing content captured in Burp Suite, similar to the "copy as curl request" option. 

![image](https://github.com/CIPHERVUE/BURP-TO-SQLMAP/assets/98955798/c88bd49a-45d1-4fc8-a385-7e639ebf17f0)


Support for Various Content Types: Automatically handles JSON, URL-encoded form data, and other MIME types.
Dynamic Command Generation: Generates sqlmap commands dynamically based on the content type and structure of HTTP requests.
Clipboard Functionality: Automatically copies the generated sqlmap command to the system clipboard.

# Installation/Compilation

## install openjdk-21
sudo apt install openjdk-21-jdk

## Download the .jar version of burpSuite
https://portswigger.net/burp/releases/

## Install Intellij IDE 
https://www.jetbrains.com/idea/download

### Set libraries path for BurpSuite - BURP-TO-SQLMAP/.idea/libraries/burpsuite_pro.xml
### default = root url="jar:///home/kali/Downloads/burpsuite_pro.jar!/" 

## Build -> Build Artifacts 

## BurpSuite -> Extensions -> Import .jar

