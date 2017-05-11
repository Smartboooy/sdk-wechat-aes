package com.github.Smartboooy.sdk.wechat.aes;

import com.github.Smartboooy.sdk.wechat.aes.exception.AesException;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Random;

/**
 * Created by 刘春龙 on 2017/4/6.
 * <p/>
 * 提供接收和推送给公众平台消息的加解密方法(UTF8编码的字符串).
 * <ol>
 * <li>第三方回复加密消息给公众平台</li>
 * <li>第三方收到公众平台发送的消息，验证消息的安全性，并对消息进行解密。</li>
 * </ol>
 */
public class WXBizMsgCrypt {

    public static final Logger logger = LoggerFactory.getLogger(WXBizMsgCrypt.class);

    static Charset CHARSET = Charset.forName("utf-8");

    Base64 base64 = new Base64();

    private String token;//公众平台上，开发者设置的token
    private String appId;//公众平台appid
    byte[] aesKey;//AES密钥
    /**
     * 构造函数
     * @param token 公众平台上，开发者设置的token
     * @param encodingAesKey 公众平台上，开发者设置的EncodingAESKey，该值为Base64编码后的可见字符串
     * @param appId 公众平台appid
     * @throws AesException 执行失败，请查看该异常的错误码和具体的错误信息
     */
    public WXBizMsgCrypt(String token, String encodingAesKey, String appId) throws AesException {

        // EncodingAESKey长度固定为43个字符，从a-z,A-Z,0-9共62个字符中选取，公众帐号可以在公众平台的开发者中心的服务器配置修改
        if (encodingAesKey.length() != 43) {
            throw new AesException(AesException.IllegalAesKey);
        }

        this.token = token;
        this.appId = appId;

        // AES密钥：AESKey=Base64_Decode(EncodingAESKey + "=")，EncodingAESKey尾部填充一个字符的"=",
        // 用Base64_Decode生成32个字节的AESKey
        aesKey = Base64.decodeBase64(encodingAesKey + "=");
    }


    /**
     * 将公众平台（公众号）回复用户的消息加密打包.
     *
     * <ol>
     * <li>对要发送的消息进行AES-CBC加密</li>
     * <li>生成安全签名</li>
     * <li>将消息密文和安全签名打包成xml格式</li>
     * </ol>
     * @param replyMsg 公众平台（公众号）待回复用户的消息，xml格式的字符串
     * @param timeStamp 时间戳，可以自己生成，也可以用URL参数的timestamp
     * @param nonce 随机串，可以自己生成，也可以用URL参数的nonce
     * @return 加密后的可以直接回复用户的密文，包括msg_signature, timestamp, nonce, encrypt的xml格式的字符串
     * @throws AesException 执行失败，请查看该异常的错误码和具体的错误信息
     */
    public String encryptMsg(String replyMsg, String timeStamp, String nonce) throws AesException {
        // 加密
        String encrypt = encrypt(getRandomStr(), replyMsg);

        if (timeStamp == "") {
            timeStamp = Long.toString(System.currentTimeMillis());
        }

        // 生成安全签名
        String signature = SHA1.getSHA1(token, timeStamp, nonce, encrypt);

        // 生成发送的xml
        String result = XMLParse.generate(encrypt, signature, timeStamp, nonce);

        return result;
    }


    /**
     * 对"明文"进行加密.<br>
     * "明文"指AES加密的buf，buf = randomStrBytes + networkBytesOrder + textBytes + appidBytes，有区别于"Msg消息明文"<br>
     * 加密流程：<br>
     *     <ol>
     *         <li>首先，组装AES加密的buf，buf表达式：16个字节的"随机字符串"的字节数组 + 4个字节的网络字节序 + "Msg消息明文"的字节数组 + "AppID"的字节数组</li>
     *         <li>补齐buff字节数组。填充策略：数据采用PKCS#7填充；PKCS#7：K为秘钥字节数（采用32），buf明文字节数组，N为其字节数。Buf需要被填充为K的整数倍。在buf的尾部填充(K-N%K)个字节，每个字节的内容是(K- N%K)；</li>
     *         <li>AES的CBC模式加密补齐后的字节数组</li>
     *         <li>使用BASE64对加密后的字节数组进行编码，使其成为可见字符串</li>
     *     </ol>
     *
     * @param randomStr 16个字节的随机字符串
     * @param text Msg消息明文
     * @return 加密后base64编码的字符串
     * @throws AesException aes加密失败
     */
    private String encrypt(String randomStr, String text) throws AesException {
        ByteGroup byteCollector = new ByteGroup();

        byte[] randomStrBytes = randomStr.getBytes(CHARSET);//16个字节的随机字符串的字节数组
        byte[] textBytes = text.getBytes(CHARSET);//待加密的"Msg消息明文"的字节数组
        byte[] networkBytesOrder = getNetworkBytesOrder(textBytes.length);//根据"Msg消息明文"的字节数组长度，获取网络字节序
        byte[] appidBytes = appId.getBytes(CHARSET);//"AppID"的字节数组

        // AES加密的buf由16个字节的随机字符串(randomStr)的字节数组、4个字节的网络字节序(根据"Msg消息明文"的字节数组长度，获取网络字节序)、text（Msg消息明文）和appId组成
        // randomStrBytes + networkBytesOrder + textBytes + appidBytes
        byteCollector.addBytes(randomStrBytes);
        byteCollector.addBytes(networkBytesOrder);
        byteCollector.addBytes(textBytes);
        byteCollector.addBytes(appidBytes);

        // ... + padBytes(补齐用的字节数组): 使用自定义的填充方式对明文进行补位填充
        byte[] padBytes = PKCS7Encoder.encode(byteCollector.size());
        byteCollector.addBytes(padBytes);

        // 获得最终的字节流, 未加密
        byte[] unencrypted = byteCollector.toBytes();

        try {

            // 设置加密模式为AES的CBC模式
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            //key - 密钥的密钥内容。algorithm - 与给定的密钥内容相关联的密钥算法的名称。
            SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
            //iv - 具有 IV 的缓冲区。offset - iv 中的偏移量，IV 从此处开始。len - IV 字节的数目。
            IvParameterSpec iv = new IvParameterSpec(aesKey, 0, 16);
            //opmode - 此 Cipher 的操作模式（为以下之一：ENCRYPT_MODE、DECRYPT_MODE、WRAP_MODE 或 UNWRAP_MODE）。key - 加密密钥。params - 算法参数
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);
            // 加密
            byte[] encrypted = cipher.doFinal(unencrypted);

            // 使用BASE64对加密后的字节数组进行编码，生成可见字符串
            String base64Encrypted = base64.encodeToString(encrypted);

            return base64Encrypted;

        } catch (Exception e) {
            e.printStackTrace();
            throw new AesException(AesException.EncryptAESError);
        }

    }

    /**
     * 检验消息的真实性，并且获取解密后的明文.
     * <ol>
     * <li>利用收到的密文生成安全签名，进行签名验证</li>
     * <li>若验证通过，对消息进行解密</li>
     * </ol>
     *
     * @param msgSignature 签名串，对应URL参数的msg_signature
     * @param timeStamp 时间戳，对应URL参数的timestamp
     * @param nonce 随机串，对应URL参数的nonce
     * @param postData xml消息体
     * @return
     */
    public String decryptMsg(String msgSignature, String timeStamp, String nonce, String postData)
            throws AesException {

        // 提取密文
        Object[] encrypt = XMLParse.extract(postData);

        // 验证安全签名
        String signature = SHA1.getSHA1(token, timeStamp, nonce, encrypt[1].toString());

        // 和URL中的签名比较是否相等
        logger.info("第三方收到URL中的签名：" + msgSignature);
        logger.info("第三方校验签名：" + signature);

        if (!signature.equals(msgSignature)) {
            throw new AesException(AesException.ValidateSignatureError);
        }

        // 解密
        String result = decrypt(encrypt[1].toString());
        return result;
    }


    /**
     * 对密文进行解密.
     * @param text 需要解密的密文
     * @return 解密得到的明文
     * @throws AesException aes解密失败
     */
    private String decrypt(String text) throws AesException {

        String xmlContent, from_appid;
        byte[] original;
        try {

            // 设置解密模式为AES的CBC模式
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            //key - 密钥的密钥内容。algorithm - 与给定的密钥内容相关联的密钥算法的名称。
            SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
            //iv - 具有 IV 的缓冲区。offset - iv 中的偏移量，IV 从此处开始。len - IV 字节的数目。
            IvParameterSpec iv = new IvParameterSpec(aesKey, 0, 16);
            //opmode - 此 Cipher 的操作模式（为以下之一：ENCRYPT_MODE、DECRYPT_MODE、WRAP_MODE 或 UNWRAP_MODE）。key - 加密密钥。params - 算法参数
            cipher.init(Cipher.DECRYPT_MODE, keySpec, iv);

            // 使用BASE64对密文进行解码（密文使用Base64编码）
            byte[] encrypted = Base64.decodeBase64(text);

            // 解密
            original = cipher.doFinal(encrypted);

            // 去除补位字符
            // AES加密的buf由16个字节的随机字符串(randomStr)的字节数组、4个字节的网络字节序(根据"Msg消息明文"的字节数组长度，获取网络字节序)、text（Msg消息明文）和appId组成.
            // 表达式：buf = randomStrBytes + networkBytesOrder + textBytes + appidBytes
            byte[] bytes = PKCS7Encoder.decode(original);

            // 分离16个字节的随机字符串，网络字节序和AppID
            byte[] networkOrder = Arrays.copyOfRange(bytes, 16, 20);//四位网络字节序
            int xmlLength = recoverNetworkBytesOrder(networkOrder);//通过"网络字节序"获取"Msg消息明文"的字节数组长度
            xmlContent = new String(Arrays.copyOfRange(bytes, 20, 20 + xmlLength), CHARSET);//"Msg消息明文"
            from_appid = new String(Arrays.copyOfRange(bytes, 20 + xmlLength, bytes.length), CHARSET);//消息来自哪个AppID

        } catch (Exception e) {
            e.printStackTrace();
            throw new AesException(AesException.DecryptAESError);
        }

        // appid不相同的情况
        if (!from_appid.equals(appId)) {
            throw new AesException(AesException.ValidateAppidError);
        }
        return xmlContent;
    }

    /**
     * 验证URL，验证服务器地址的有效性
     * <p/>
     * 开发者通过检验signature对请求进行校验。若确认此次GET请求来自微信服务器，请原样返回echostr参数内容，则接入生效，成为开发者成功，否则接入失败。
     *
     * @param msgSignature 签名串，对应URL参数的msg_signature。msg_signature结合了开发者填写的token参数和请求中的timestamp参数、nonce参数。
     * @param timeStamp 时间戳，对应URL参数的timestamp
     * @param nonce 随机串，对应URL参数的nonce
     * @param echoStr 随机串，对应URL参数的echostr
     * @return 解密之后的echostr
     * @throws AesException 执行失败，请查看该异常的错误码和具体的错误信息
     */
    public String verifyUrl(String msgSignature, String timeStamp, String nonce, String echoStr)
            throws AesException {
        String signature = SHA1.getSHA1(token, timeStamp, nonce, echoStr);

        if (!signature.equals(msgSignature)) {
            throw new AesException(AesException.ValidateSignatureError);
        }

        String result = decrypt(echoStr);
        return result;
    }



    /**
     * 根据"Msg消息明文"的字节数组长度，生成4个字节的网络字节序
     * @param sourceNumber "Msg消息明文"的字节数组长度
     * @return 网络字节序
     */
    private byte[] getNetworkBytesOrder(int sourceNumber) {

        //字节数组，数组大小4，每个字节为8位，正好存储一个"32位的int"。
        byte[] orderBytes = new byte[4];

        //将"32位的int"按位，从低位到高位分段存储，每一分段8位，即一个字节。
        orderBytes[3] = (byte) (sourceNumber & 0xFF);//取低8位
        orderBytes[2] = (byte) (sourceNumber >> 8 & 0xFF);//右移8位，高8位补0，再取低8位
        orderBytes[1] = (byte) (sourceNumber >> 16 & 0xFF);
        orderBytes[0] = (byte) (sourceNumber >> 24 & 0xFF);
        return orderBytes;
    }

    /**
     * 还原4个字节的网络字节序
     * @param orderBytes 网络字节序
     * @return "Msg消息明文"的字节数组长度
     */
    private int recoverNetworkBytesOrder(byte[] orderBytes) {
        int sourceNumber = 0;//初始化为0
        for (int i = 0; i < 4; i++) {
            sourceNumber <<= 8;//先左移8位，低8位补0

            //orderBytes[i] & 0xff : 转为32位的int，低8位和8位byte一致，其它高24位全为0. 然后`或运算`，
            //由于`sourceNumber`的低8位都为0，并且"orderBytes[i] & 0xff"的高24位也都为0，故，执行或运算，结果32位int是`sourceNumber`的高24位 + `orderBytes[i] & 0xff`的低8位
            sourceNumber |= orderBytes[i] & 0xff;
        }
        return sourceNumber;
    }

    /**
     * 随机生成16个字节的字符串
     * @return
     */
    private String getRandomStr() {
        String base = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        Random random = new Random();//生成随机数
        StringBuffer sbuffer = new StringBuffer();
        for (int i = 0; i < 16; i++) {
            int number = random.nextInt(base.length());
            sbuffer.append(base.charAt(number));
        }
        return sbuffer.toString();
    }
}
