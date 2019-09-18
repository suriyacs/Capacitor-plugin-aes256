package com.ideas2it.aes256;

import android.util.Base64;

import com.getcapacitor.JSObject;
import com.getcapacitor.NativePlugin;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;

import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import shaded.org.apache.commons.codec.binary.Hex;


/**
 * This class used to perform AES encryption and decryption.
 */
@NativePlugin()
public class AES256 extends Plugin {
    private static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS5PADDING";
    private static final int PBKDF2_ITERATION_COUNT = 1001;
    private static final int PBKDF2_KEY_LENGTH = 256;
    private static final int SECURE_IV_LENGTH = 64;
    private static final int SECURE_KEY_LENGTH = 128;
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA1";
    private static final String PBKDF2_SALT = "hY0wTq6xwc6ni01G";
    private static final Random RANDOM = new SecureRandom();

    /**
     * <p>
     *  Perform encryption
     * </p>
     *
     * @param PluginCall The plugin call
     * @return Secure Key
     * @throws Exception
     */
    @PluginMethod()
    public void encrypt(PluginCall call) {
        String secureKey = call.getString("secureKey");
        String iv = call.getString("iv");
        String value = call.getString("value");
        try {
            JSObject result = new JSObject();
            if (secureKey != null && secureKey.length() != 0 &&
                iv != null && iv.length() != 0 &&
                value != null && value.length() != 0) {
                result.put("response", performEncrypt(secureKey, value, iv));
                call.resolve(result);
            } else {
                call.reject("Please check your secureKey or iv or value to encrypt!!!");
            }            
        } catch(Exception e) {
            System.out.println("Error occurred while performing encryption : " + e.getMessage());
            call.reject("Error occurred while performing encryption");
        }
    }

    /**
     * <p>
     *  Perform decryption
     * </p>
     *
     * @param PluginCall The plugin call
     * @return Secure Key
     * @throws Exception
     */
    @PluginMethod()
    public void decrypt(PluginCall call) {
        String secureKey = call.getString("secureKey");
        String iv = call.getString("iv");
        String value = call.getString("value");
        try {
            JSObject result = new JSObject();
            if (secureKey != null && secureKey.length() != 0 &&
                iv != null && iv.length() != 0 &&
                value != null && value.length() != 0) {
                result.put("response", performDecrypt(secureKey, value, iv));
                call.resolve(result);
            } else {
                call.reject("Please check your secureKey or iv or value to decrypt!!!");
            }            
        } catch(Exception e) {
            System.out.println("Error occurred while performing decryption : " + e.getMessage());
            call.reject("Error occurred while performing decryption");
        }
    }

    /**
     * <p>
     *  Plugin method to generate secure key based in password
     * </p>
     *
     * @param PluginCall The plugin call
     * @return Secure Key
     * @throws Exception
     */
    @PluginMethod()
    public void generateSecureKey(PluginCall call) {
        String password = call.getString("password");
        try {
            JSObject result = new JSObject();
            if (password != null && password.length() != 0) {
                result.put("response", getSecureKey(password));
                call.resolve(result);
            } else {
                call.reject("Please give password!!!");
            }            
        } catch(Exception e) {
            System.out.println("Error occurred while generating secure key : " + e.getMessage());
            call.reject("Error occurred while generating secure key ");
        }
    }

    /**
     * <p>
     *  Plugin method to generate secure IV based in password
     * </p>
     *
     * @param PluginCall The plugin call
     * @return SecureIv
     * @throws Exception
     */
    @PluginMethod()
    public void generateSecureIv(PluginCall call) {
        String password = call.getString("password");
        try {
            JSObject result = new JSObject();
            if (password != null && password.length() != 0) {
                result.put("response", getSecureIv(password));
                call.resolve(result);
            } else {
                call.reject("Please give password!!!");
            }            
        } catch(Exception e) {
            System.out.println("Error occurred while generating secure Iv : " + e.getMessage());
            call.reject("Error occurred while generating secure Iv ");
        }
    }

    /**
     * <p>
     * To perform the AES256 encryption
     * </p>
     *
     * @param secureKey A 32 bytes string, which will used as input key for AES256 encryption
     * @param value     A string which will be encrypted
     * @param iv        A 16 bytes string, which will used as initial vector for AES256 encryption
     * @return AES Encrypted string
     * @throws Exception
     */
    private String performEncrypt(String secureKey, String value, String iv) throws Exception {
        byte[] pbkdf2SecuredKey = generatePBKDF2(secureKey.toCharArray(), PBKDF2_SALT.getBytes("UTF-8"),
                PBKDF2_ITERATION_COUNT, PBKDF2_KEY_LENGTH);

        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
        SecretKeySpec secretKeySpec = new SecretKeySpec(pbkdf2SecuredKey, "AES");

        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] encrypted = cipher.doFinal(value.getBytes());

        return Base64.encodeToString(encrypted, Base64.DEFAULT);
    }

    /**
     * <p>
     * To perform the AES256 decryption
     * </p>
     *
     * @param secureKey A 32 bytes string, which will used as input key for AES256 decryption
     * @param value     A 16 bytes string, which will used as initial vector for AES256 decryption
     * @param iv        An AES256 encrypted data which will be decrypted
     * @return AES Decrypted string
     * @throws Exception
     */
    private String performDecrypt(String secureKey, String value, String iv) throws Exception {
        byte[] pbkdf2SecuredKey = generatePBKDF2(secureKey.toCharArray(), PBKDF2_SALT.getBytes("UTF-8"),
                PBKDF2_ITERATION_COUNT, PBKDF2_KEY_LENGTH);

        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
        SecretKeySpec secretKeySpec = new SecretKeySpec(pbkdf2SecuredKey, "AES");

        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] original = cipher.doFinal(Base64.decode(value, Base64.DEFAULT));

        return new String(original);
    }

    /**
     * <p>
     * This method used to generate the secure key based on the PBKDF2 algorithm
     * </p>
     *
     * @param password The password
     * @return SecureKey
     * @throws Exception
     */
    private static String getSecureKey(String password) throws Exception {
        byte[] secureKeyInBytes = generatePBKDF2(password.toCharArray(), generateRandomSalt(),
                PBKDF2_ITERATION_COUNT, SECURE_KEY_LENGTH);
        return Hex.encodeHexString(secureKeyInBytes);
    }

    /**
     * <p>
     * This method used to generate the secure IV based on the PBKDF2 algorithm
     * </p>
     *
     * @param password The password
     * @return SecureIV
     * @throws Exception
     */
    private static String getSecureIv(String password) throws Exception {
        byte[] secureIVInBytes = generatePBKDF2(password.toCharArray(), generateRandomSalt(),
                PBKDF2_ITERATION_COUNT, SECURE_IV_LENGTH);
        return Hex.encodeHexString(secureIVInBytes);
    }

    /**
     * <p>
     * This method used to generate the random salt
     * </p>
     *
     * @return
     */
    private static byte[] generateRandomSalt() {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        return salt;
    }

    /**
     * @param password       The password
     * @param salt           The salt
     * @param iterationCount The iteration count
     * @param keyLength      The length of the derived key.
     * @return PBKDF2 secured key
     * @throws Exception
     * @see <a href="https://docs.oracle.com/javase/8/docs/api/javax/crypto/spec/PBEKeySpec.html">
     * https://docs.oracle.com/javase/8/docs/api/javax/crypto/spec/PBEKeySpec.html</a>
     */
    private static byte[] generatePBKDF2(char[] password, byte[] salt, int iterationCount,
                                         int keyLength) throws Exception {
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
        KeySpec keySpec = new PBEKeySpec(password, salt, iterationCount, keyLength);
        SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);
        return secretKey.getEncoded();
    }
}
