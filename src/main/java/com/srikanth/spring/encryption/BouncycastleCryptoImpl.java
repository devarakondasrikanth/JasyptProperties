package com.srikanth.spring.encryption;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jasypt.encryption.StringEncryptor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.stereotype.Component;
@Component
public class BouncycastleCryptoImpl extends BCryptPasswordEncoder implements BouncycastleCrypto,StringEncryptor{
	
	static{
		Security.addProvider(new  BouncyCastleProvider());
	}
	
	private final Log log = LogFactory.getLog(getClass());
	
	
	@Override
	public String encrypt(String plainText){
		log.info("Encrypting plainText using Bouncy Castle");
		byte[] clean = plainText.getBytes();
        // Generating IV.
        int ivSize = 16;
        byte[] iv = new byte[ivSize];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        SecretKeySpec secretKeySpec;
        byte[] encrypted = null;
		try {
			secretKeySpec = (SecretKeySpec) CryptoUtility.getKey();
			// Encrypt.
	        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding","BC");
	        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
	        encrypted = cipher.doFinal(clean);
		} catch (NoSuchAlgorithmException | IOException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | NoSuchProviderException e) {
			log.warn("Exception while encrypting data "+e.getMessage());			
		}
        
        // Combine IV and encrypted part.
        byte[] encryptedIVAndText = new byte[ivSize + encrypted.length];
        System.arraycopy(iv, 0, encryptedIVAndText, 0, ivSize);
        System.arraycopy(encrypted, 0, encryptedIVAndText, ivSize, encrypted.length);
        //Base64 Encoding
        return new String(Base64.encode(encryptedIVAndText));
	}

	@Override
	public String decrypt(String encryptedText){	
		if(CryptoUtility.checkStringStartingwithENC(encryptedText)){
			log.info("Decrypting encryptedText with ENC( prefix using Bouncy Castle");
			return decryptString(CryptoUtility.removePrefixAndSuffix(encryptedText));
		}else{
			log.info("Decrypting encryptedText using Bouncy Castle");
			return decryptString(encryptedText);
		}
		
	}
	
	@Override
	public boolean matches(CharSequence rawPassword, String encodedPassword) {
		if(decrypt(encodedPassword).equals(rawPassword)){
			return true;
		}else{
			return false;
		}
	}
	
	private String decryptString(String encryptedText){
		int ivSize = 16;
        //Base64 Decoding
        byte[] encryptedIvTextBytes = Base64.decode(encryptedText.getBytes());
        // Extract IV.
        byte[] iv = new byte[ivSize];
        System.arraycopy(encryptedIvTextBytes, 0, iv, 0, iv.length);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        // Extract encrypted part.
        int encryptedSize = encryptedIvTextBytes.length - ivSize;
        byte[] encryptedBytes = new byte[encryptedSize];
        System.arraycopy(encryptedIvTextBytes, ivSize, encryptedBytes, 0, encryptedSize);
        SecretKeySpec secretKeySpec;
        byte[] decrypted = null;
		try {
			secretKeySpec = (SecretKeySpec) CryptoUtility.getKey();
			Cipher cipherDecrypt = Cipher.getInstance("AES/CBC/PKCS7Padding","BC");
	        cipherDecrypt.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
	        decrypted = cipherDecrypt.doFinal(encryptedBytes);
		} catch (NoSuchAlgorithmException | IOException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | NoSuchProviderException e) {
			log.warn("Exception while decrypting data "+e.getMessage());	
		}        

        return new String(decrypted);
	}
	
	
	
	
}
