## 文档
微信公众平台文档：https://mp.weixin.qq.com/wiki<br>
微信开放平台文档：https://open.weixin.qq.com/cgi-bin/showdocument?action=dir_list&t=resource/res_list&verify=1&lang=zh_CN

## 前言
>注：针对org.apache.commons.codec.binary.Base64，<br>
   需要导入jar包commons-codec-1.9（或commons-codec-1.8等其他版本）<br>
   官方下载地址：http://commons.apache.org/proper/commons-codec/download_codec.cgi
   
## 功能简述

### 提供接收和推送给公众平台消息的加解密接口(UTF8编码的字符串).

- 第三方回复加密消息给公众平台
- 第三方收到公众平台发送的消息，验证消息的安全性，并对消息进行解密。

说明：异常java.security.InvalidKeyException:illegal Key Size的解决方案

>因为某些国家的进口管制限制，Java发布的运行环境包中的加解密有一定的限制。
比如默认不允许256位密钥的AES加解密，解决方法就是修改策略文件。

官方网站提供了JCE无限制权限策略文件的下载：

- JDK6的下载地址：
http://www.oracle.com/technetwork/java/javase/downloads/jce-6-download-429243.html

- JDK7的下载地址：
http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html

- JDK8的下载地址：
http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html

下载后解压，可以看到local_policy.jar和US_export_policy.jar以及readme.txt

- 如果安装了JRE，将两个jar文件放到%JRE_HOME%\lib\security目录下覆盖原来的文件。
- 如果安装了JDK，将两个jar文件放到%JDK_HOME%\jre\lib\security目录下覆盖原来文件。


