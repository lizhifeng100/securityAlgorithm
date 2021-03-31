package util;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.security.SecureRandom;

/**
 * @Description 对称加密，需要key ：password这种加密。
 * @Date 2021/3/30 15:34
 * @Created by 荔枝/260494
 */
public class DESUtil {

    /**
     * 加密
     */
    private static byte[] encrypt(byte[] data, byte[] key) throws Exception {
        //生成一个可以信任的随机数源
        SecureRandom secureRandom = new SecureRandom();
        //从原始密匙数据创建DESkeySpec对象。
        DESKeySpec deSKeySpec = new DESKeySpec(key);

        //创建一个密匙工厂，然后用它把DESKeySpec转换成SecretKey对象
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        SecretKey secretKey = keyFactory.generateSecret(deSKeySpec);

        //Cipher对象实际完成加密工作
        Cipher cipher = Cipher.getInstance("DES");

        //用密钥初始化Cipher
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, secureRandom);

        return cipher.doFinal(data);
    }

    /**
     * 根据键值解密
     */
    private static byte[] decrypt(byte[] data, byte[] key) throws Exception {
        //生成一个可以信任的随机数源
        SecureRandom secureRandom = new SecureRandom();

        //从原始密钥数据创建DESKeySpec对象
        DESKeySpec desKeySpec = new DESKeySpec(key);

        //创建一个密钥工厂，然后用它把DESKeySpec转换成SecretKey对象
        SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
        SecretKey secretKey = factory.generateSecret(desKeySpec);

        //Cipher对象实际完成解密操作
        Cipher cipher = Cipher.getInstance("DES");

        cipher.init(Cipher.DECRYPT_MODE, secretKey, secureRandom);
        return cipher.doFinal(data);
    }

    public static String decrypt(String data, String key) throws Exception {
        if (data == null)
            return null;
        BASE64Decoder decoder = new BASE64Decoder();
        byte[] buf = decoder.decodeBuffer(data);
        byte[] decrypt = decrypt(buf, key.getBytes());
        return new String(decrypt);
    }

    public static String encrypt(String data, String key) throws Exception {
        byte[] encrypt = encrypt(data.getBytes(), key.getBytes());
        return new BASE64Encoder().encode(encrypt);
    }

    public static void main(String[] args) throws Exception {
        String key = "wew2323w233321ws233w";
        String password = "Bb@136320";
        String encrypt = encrypt(password, key);
        System.out.println(encrypt);
        String decrypt = decrypt(encrypt, key);
        System.out.println(decrypt);
    }

}
