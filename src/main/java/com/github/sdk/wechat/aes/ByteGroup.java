package com.github.sdk.wechat.aes;

import java.util.ArrayList;

/**
 * Created by 刘春龙 on 2017/4/6.
 */
public class ByteGroup {

    private ArrayList<Byte> byteContainer = new ArrayList<Byte>();//字节容器

    public byte[] toBytes() {
        byte[] bytes = new byte[byteContainer.size()];
        for (int i = 0; i < byteContainer.size(); i++) {
            bytes[i] = byteContainer.get(i);
        }
        return bytes;
    }

    public ByteGroup addBytes(byte[] bytes) {
        for (byte b : bytes) {
            byteContainer.add(b);
        }
        return this;
    }

    public int size() {
        return byteContainer.size();
    }
}
