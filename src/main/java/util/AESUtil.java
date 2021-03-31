package util;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * @Description TODO
 * @Date 2021/3/30 16:32
 * @Created by 荔枝/260494
 */
public class AESUtil {

    final static String algorithm = "AES";

    public static String encrypt(String data, String key) throws Exception, NoSuchAlgorithmException {

        byte[] dataToSend = data.getBytes();
        Cipher cipher = Cipher.getInstance(algorithm);
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encryptedData = cipher.doFinal(dataToSend);
        byte[] encode = Base64.getEncoder().encode(encryptedData);

        return new String(encode);
    }

    public static String decrypt(String data, String key) throws Exception {

        byte[] encryptedData = Base64.getDecoder().decode(data);
        Cipher cipher = Cipher.getInstance(algorithm);
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), algorithm);
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] bytes = cipher.doFinal(encryptedData);
        return new String(bytes);
    }

    public static void main(String[] args) throws Exception {
        String password = "Bb@136320";
        String key = "w@#$4@#$s^&3*&^5";
        String encrypt = encrypt(password, key);
        System.out.println(encrypt);
        String decrypt = decrypt(encrypt, key);
        System.out.println(decrypt);
    }

}
