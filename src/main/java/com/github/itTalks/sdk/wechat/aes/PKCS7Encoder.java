package com.github.itTalks.sdk.wechat.aes;

import java.nio.charset.Charset;
import java.util.Arrays;

/**
 * Created by 刘春龙 on 2017/4/6.
 *
 * 提供基于PKCS7算法的加解密方法.
 */
public class PKCS7Encoder {

    static Charset CHARSET = Charset.forName("utf-8");

    static int BLOCK_SIZE = 32;//秘钥字节数（默认，采用32）

    /**
     * 获得对"明文"进行补位填充的字节数组.<br>
     * ... + padBytes: 使用自定义的填充方式对明文进行补位填充.<br>
     * 填充策略：数据采用PKCS#7填充；<br>
     * PKCS#7：K为秘钥字节数（采用32），buf为待加密的内容（即"明文"），N为其字节数。
     * buf需要被填充为K的整数倍。在buf的尾部填充(K-N%K)个字节，每个字节的内容是(K- N%K)；<br>
     *
     * @param n 需要进行填充补位操作的"明文"字节个数
     * @return 补齐用的字节数组
     */
    public static byte[] encode(int n) {
        // 计算需要填充的位数
        int amountToPad = BLOCK_SIZE - (n % BLOCK_SIZE);//取值区间为(0, BLOCK_SIZE]，即(0, 32]
        if (amountToPad == 0) {
            amountToPad = BLOCK_SIZE;
        }

        // 获得补位所用的字符，ascii码(0, 32]区间的字符
        char padChr = chr(amountToPad);

        String tmp = new String("");
        for (int index = 0; index < amountToPad; index++) {
            tmp += padChr;
        }
        return tmp.getBytes(CHARSET);
    }


    /**
     * 去除补位
     * @param decrypted 补位后的字节数组
     * @return 去除补位后的字节数组
     */
    public static byte[] decode(byte[] decrypted) {
        //PKCS#7数据填充时，使用的策略是在buf的尾部填充(K-N%K)个字节，每个字节的内容是(K- N%K)。
        //故，根据字节数组的最后一位字节，即可知道填充的字节数量。
        //取值区间为(0, BLOCK_SIZE]，即(0, 32]，[1, 32]
        byte padByte = decrypted[decrypted.length - 1];

        int pad = padByte & 0xff;

        if (pad < 1 || pad > 32) {
            pad = 0;
        }

        return Arrays.copyOfRange(decrypted, 0, decrypted.length - pad);
    }

    /**
     * 将数字转化成ASCII码对应的字符，用于对明文进行补位填充<br>
     *
     * <br>
     * 说明：在buf的尾部填充(K-N%K)个字节，每个字节的内容是(K-N%K)，即参数num的取值范围为(0，K]，又K为秘钥字节数（采用32），所以num取值范围(0,32]。<br>
     * 故，32位的int类型num转为8位的char类型，只需要保留后8位即可。
     *
     * @param num 需要转化的数字
     * @return 转化得到的字符
     */
    private static char chr(int num) {
        /**
         * int为32位，byte为8位。将int转为byte，只保留最后8位。
         * 0xFF：32位，前24位都为0，后8位都为1。
         * int&0xFF并强制类型转为byte，结果只需保留最后有用的8位即可。
         */
        byte target = (byte) (num & 0xFF);
        return (char) target;
    }
}
