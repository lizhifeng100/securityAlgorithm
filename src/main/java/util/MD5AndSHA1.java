package util;

import java.security.MessageDigest;

/**
 * @Description TODO
 * @Date 2021/3/30 11:20
 * @Created by 荔枝/260494
 */
public class MD5AndSHA1 {


    private static final String hexDigits[] = {"0", "1", "2", "3", "4", "5",
            "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"};

    public static void main(String[] args) throws Exception {
        String s = strMD5("Bb@136320");
        System.out.println(s);
    }

    public static String strMD5(String str) throws Exception {

        //拿到一个MD5转换器（如果想要SHA1参数换成”SHA1”）
//        MessageDigest md = MessageDigest.getInstance("MD5");
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        // 输入的字符串转换成字节数组
        byte[] bytes = str.getBytes();
        md.update(bytes);
        byte[] digest = md.digest();
        return byteArrayToHexString(digest);
    }


    //这里主要是遍历8个byte，转化为16位进制的字符，即0-F
    private static String byteArrayToHexString(byte b[]) {
        StringBuffer resultSb = new StringBuffer();
        for (int i = 0; i < b.length; i++)
            resultSb.append(byteToHexString(b[i]));
        return resultSb.toString();
    }

    private static String byteToHexString(byte b) {
        int n = b;
        if (n < 0)
            n += 256;
        int d1 = n / 16;
        int d2 = n % 16;
        return hexDigits[d1] + hexDigits[d2];
    }
}


