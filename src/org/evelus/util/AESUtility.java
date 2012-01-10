package org.evelus.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.jar.JarOutputStream;
import java.util.jar.Pack200;
import java.util.zip.GZIPInputStream;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AESUtility.java
 * @version 1.0.0
 * @author Evelus Development (SiniSoul)
 */
public final class AESUtility {
    
    /**
     * The encoding table.
     */
    private static int[] t;
    
    /**
     * Encodes the characters from a string into a byte array.
     * @param s The key to encode.
     * @return The encoded array.
     */
    private static byte[] encode(String s) { 
        int len;
        byte[] array = null;
        if (s.length() > 0) {
            len = 3 * ((s.length() + 3) / 4) - 2;
            array = new byte[len];
            encode(array, 0, s);
        }
        return array;
    }

    /**
     * Encodes the characters from a string into a byte array.
     * @param dest The destination array.
     * @param off The offset in the destination array.
     * @param s The string to encode.
     * @return The difference in the amount of characters encoded and the offset.
     */
    private static int encode(byte[] dest, int off, String s) {
        int len = s.length();
        int oldOff = off;
        int pos = 0;
        while(len > pos) {
            int k0 = -1, k1 = -1, k2 = -1, k3 = -1;
            if(pos < len) {
                char c = s.charAt(pos);
                k0 = c >= 0 && c < t.length ? t[c] : -1;
            }
            if(pos + 1 < len) {
                char c = s.charAt(pos + 1);
                k1 = c >= 0 && c < t.length ? t[c] : -1;
            }
            if(pos + 2 < len) {
                char c = s.charAt(pos + 2);
                k2 = c >= 0 && c < t.length ? t[c] : -1;
            }
            if(pos + 3 < len) {
                char c = s.charAt(pos + 3);
                k3 = c >= 0 && c < t.length ? t[c] : -1;
            }
            dest[off++] = (byte) (k0 << 2 | k1 >>> 4);
            if (k2 != -1) {
                dest[off++] = (byte) (k2 >>> 2 | 240 & k1 << 4);
                if (k3 != -1) {
                    dest[off++] = (byte) (k3 | k2 << 6 & 192);
                    pos += 4;
                    continue;
                }
            }
            break;
        }
        return off - oldOff;
    }

    /**
     * Deciphers a pack file, inner.pack.gz
     * @param input The input stream to decrypt from.
     * @param key The encryption key.
     * @param iv The initialization vector.
     * @return The deciphered pack file.
     */
    public static byte[] decipherPack(InputStream input, String key, String iv) {
        byte[] encodedKey = encode(key);
        byte[] encodedIV = encode(iv);
        Cipher cipherObject = null;
        SecretKeySpec secretKeySpec = new SecretKeySpec(encodedKey, "AES");
        try {
            cipherObject = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipherObject.init(2, secretKeySpec, new IvParameterSpec(encodedIV));
        } catch (Exception ex) {
            throw new RuntimeException("Exception thrown : "+ex);
        }
        byte[] buffer = new byte[5242880];
        int offset = 0;
        try {
            int read = 0;
            while (read != -1) {
                read = input.read(buffer, offset, 5242880 - offset);
                if(read > 0)
                    offset += read;
            }
        } catch (IOException ioex) {
            throw new RuntimeException("IOException thrown : "+ioex);
        }
        byte[] dest = new byte[offset];
        System.arraycopy(buffer, 0, dest, 0, offset);
        byte[] decryptedData = null;
        try {
            decryptedData = cipherObject.doFinal(dest);
        } catch (Exception ex) {
            throw new RuntimeException("Exception thrown : "+ex);
        }
        Pack200.Unpacker unpacker = Pack200.newUnpacker();
        ByteArrayOutputStream bos = new ByteArrayOutputStream(5242880);
        try {
            JarOutputStream jarOutput = new JarOutputStream(bos);
            GZIPInputStream gzip = new GZIPInputStream(new ByteArrayInputStream(decryptedData));
            unpacker.unpack(gzip, jarOutput);
            jarOutput.close();
        } catch (IOException ioex) {
            throw new RuntimeException("IOException thrown : "+ioex);
        }
        return bos.toByteArray();
    }

    static {
        t = new int[128];
        int incr = 0;
        while (incr < t.length) {
            t[incr] = -1;
            incr++;
        }
        incr = 65;
        while (90 >= incr) {
            t[incr] =  incr - 65;
            incr++;
        }
        incr = 97;
        while (122 >= incr) {
            t[incr] = incr - 71;
            incr++;
        }
        incr = 48;
        while (57 >= incr) {
            t[incr] = incr + 4;
            incr++;
        }
        t[42] = 62;
        t[43] = 62;
        t[45] = 63;
        t[47] = 63;
    }
}