package com.github.ongz1992.sdk.wechat.aes;

import com.github.ongz1992.sdk.wechat.aes.exception.AesException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Created by 刘春龙 on 2017/4/6.
 * <p/>
 * 提供公众平台的消息签名方法.
 */
public class SHA1 {

    /**
     * 用SHA1算法生成安全签名。签名流程：msg_signature=sha1(sort(Token、timestamp、nonce, msg_encrypt))
     * @param token 公众平台上，开发者设置的token，票据
     * @param timestamp 时间戳
     * @param nonce 随机字符串
     * @param encrypt 密文
     * @return 安全签名
     * @throws AesException 执行失败，请查看该异常的错误码和具体的错误信息
     */
    public static String getSHA1(String token, String timestamp, String nonce, String encrypt) throws AesException {

        try {

            String[] array = new String[]{token, timestamp, nonce, encrypt};
            StringBuffer sb = new StringBuffer();

            // 字符串排序
            Arrays.sort(array);

            for (int i = 0; i < 4; i++) {
                sb.append(array[i]);
            }
            String str = sb.toString();

            // SHA1签名生成
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.update(str.getBytes());
            byte[] digest = md.digest();

            StringBuffer hexstr = new StringBuffer();
            for (int i = 0; i < digest.length; i++) {
                //digest[i] & 0xFF：将字节转为int类型
                //将int类型转为16进制
                String shaHex = Integer.toHexString(digest[i] & 0xFF);
                if (shaHex.length() < 2) {
                    hexstr.append(0);
                }
                hexstr.append(shaHex);
            }
            return hexstr.toString();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new AesException(AesException.ComputeSignatureError);
        }
    }

}
