package util;


import javax.crypto.Cipher;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * @Description TODO
 * @Date 2021/3/31 10:32
 * @Created by 荔枝/260494
 */
public class RSAUtil {

    /**
     * 字节数据转字符串专用集合
     */
    private static final char[] HEX_CHAR = {'0', '1', '2', '3', '4', '5', '6',
            '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    /**
     * 随机生成密钥对
     */
    public static Map<String, String> genKeyPair() throws NoSuchAlgorithmException {

        Map<String, String> map = new HashMap<>();
        //keyPairGenerator类用于生成公钥和私钥。基于RSA算法生成对象
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        //初始化密钥对生成器，密钥大小为96~1024位
        keyPairGen.initialize(1024, new SecureRandom());
        //生成一个密钥对，保存在keyPair中
        KeyPair keyPair = keyPairGen.generateKeyPair();
        //得到私钥
        PrivateKey aPrivate = keyPair.getPrivate();
        //得到公钥
        PublicKey aPublic = keyPair.getPublic();
        String privateKeyString = new String(Base64.getEncoder().encode(aPrivate.getEncoded()));
        String publicKeyString = new String(Base64.getEncoder().encode(aPublic.getEncoded()));
        map.put("privateKey", privateKeyString);
        map.put("publicKey", publicKeyString);
        return map;
    }

    /**
     * 从字符串中加载公钥
     */
    public static RSAPublicKey loadPublicKeyByStr(String publicKeyStr) throws Exception {
        byte[] buffer = Base64.getDecoder().decode(publicKeyStr);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }

    /**
     * 从字符串中加载私钥
     */
    public static RSAPrivateKey loadPrivateKeyByStr(String privateKey) throws Exception {
        byte[] decode = Base64.getDecoder().decode(privateKey);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decode);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }

    /**
     * 公钥加密过程
     */
    public static byte[] encrypt(RSAPublicKey publicKey, byte[] plainTextData) throws Exception {
        if (publicKey == null)
            throw new Exception("加密公钥为空，请设置");
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(plainTextData);
    }

    /**
     * 私钥加密过程
     *
     * @param privateKey    私钥
     * @param plainTExtData 明文数据
     */
    public static byte[] encrypt(RSAPrivateKey privateKey, byte[] plainTExtData) throws Exception {
        if (privateKey == null)
            throw new Exception("加密私钥为空，请设置");
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(plainTExtData);
    }

    /**
     * 私钥解密过程
     *
     * @param privateKey 私钥
     * @param cipherData 密文数据
     */
    public static byte[] decrypt(RSAPrivateKey privateKey, byte[] cipherData) throws Exception {
        if (privateKey == null)
            throw new Exception("解密私钥为空，请设置");
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(cipherData);
    }

    /**
     * 公钥解密过程
     *
     * @param publicKey  公钥
     * @param cipherData 密文数据
     */
    public static byte[] decrypt(RSAPublicKey publicKey, byte[] cipherData) throws Exception {
        if (publicKey == null)
            throw new Exception("解密公钥为空，请设置");
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return cipher.doFinal(cipherData);
    }

    /**
     * 字节数据转十六进制字符串
     *
     * @param data 输入数据
     * @return 十六进制内容
     */
    public static String byteArrayToString(byte[] data) {
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < data.length; i++) {
            // 取出字节的高四位 作为索引得到相应的十六进制标识符 注意无符号右移
            stringBuilder.append(HEX_CHAR[(data[i] & 0xf0) >>> 4]);
            // 取出字节的低四位 作为索引得到相应的十六进制标识符
            stringBuilder.append(HEX_CHAR[(data[i] & 0x0f)]);
            if (i < data.length - 1) {
                stringBuilder.append(' ');
            }
        }
        return stringBuilder.toString();
    }

    public static void main(String[] args) throws Exception {
        Map<String, String> map = genKeyPair();
        String bytes = "Bb@136320";
        byte[] publicText = encrypt(loadPublicKeyByStr(map.get("publicKey")), bytes.getBytes());
        String string = new String(Base64.getEncoder().encode(publicText));
        byte[] privateKeys = decrypt(loadPrivateKeyByStr(map.get("privateKey")), Base64.getDecoder().decode(string));
        String string1 = byteArrayToString(privateKeys);

        String s = new String(privateKeys);
        System.out.println("privateKey:" + map.get("privateKey"));
        System.out.println("publicKey:" + map.get("publicKey"));
        System.out.println("原文：" + bytes);
        System.out.println("加密密文：" + string + "\n" + string.length());
        System.out.println("解密：" + s);

        System.out.println("byteArrayToString:" + string1);


    }
}
