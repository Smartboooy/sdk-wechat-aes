package com.github.fnpac.sdk.wechat.aes;

import com.github.fnpac.sdk.wechat.aes.exception.AesException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;

/**
 * Created by 刘春龙 on 2017/4/6.
 * <p/>
 * 提供提取消息格式中的密文及生成回复消息格式的接口.
 */
public class XMLParse {

    /**
     * 提取出xml数据包中的加密消息
     * @param xmltext 待提取的xml字符串
     * @return 提取出的加密消息字符串
     * @throws AesException 执行失败，请查看该异常的错误码和具体的错误信息
     */
    public static Object[] extract(String xmltext) throws AesException {
        Object[] result = new Object[3];

        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            StringReader sr = new StringReader(xmltext);
            InputSource is = new InputSource(sr);
            Document document = db.parse(is);

            Element root = document.getDocumentElement();
            NodeList nodeListEncrypt = root.getElementsByTagName("Encrypt");
            NodeList nodeListToUserName = root.getElementsByTagName("ToUserName");

            result[0] = 0;
            result[1] = nodeListEncrypt.item(0).getTextContent();
            result[2] = nodeListToUserName.item(0).getTextContent();
            return result;

        } catch (Exception e) {
            e.printStackTrace();
            throw new AesException(AesException.ParseXmlError);
        }
    }

    /**
     * 生成xml消息
     * @param encrypt 加密后的消息密文
     * @param signature 安全签名
     * @param timestamp 时间戳
     * @param nonce 随机字符串
     * @return 生成的xml字符串
     */
    public static String generate(String encrypt, String signature, String timestamp, String nonce) {
        //CDATA 部分由 "<![CDATA[" 开始，由 "]]>" 结束;
        //`$`代表被格式化的参数索引，eg：("%1$d,%2$s", 99,"abc") 结果：99,abc;
        String format = "<xml>\n" + "<Encrypt><![CDATA[%1$s]]></Encrypt>\n"
                + "<MsgSignature><![CDATA[%2$s]]></MsgSignature>\n"
                + "<TimeStamp>%3$s</TimeStamp>\n" + "<Nonce><![CDATA[%4$s]]></Nonce>\n" + "</xml>";
        return String.format(format, encrypt, signature, timestamp, nonce);
    }
}
