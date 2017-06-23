package com.srikanth.spring.encryption;

import java.io.File;
import java.io.IOException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;


import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;


import static org.apache.commons.io.FileUtils.*;

public class CryptoUtility {
	
		private static final String KeyFileName = "C:\\Key\\EncryptionKey.dat";
		 private static String prefix = "ENC(";		    
		 private static String suffix = ")";
		public static Key getKey() throws NoSuchAlgorithmException, IOException{
			if(checkIfKeyFileExists()){
				//read key from file and return Key
				return loadKey();
			}else{
				//generate a key and store it in file and return the key
				Key key = generateKey();
				storeKey(key);
				return key;
			}
		}
	
		
		//Initially Generate a Key and store in C:/Key as EncryptionKey.dat file
	
		public static boolean checkIfKeyFileExists(){
			File file = new File(CryptoUtility.KeyFileName);
			return file.exists();
		}
		
		public static Key generateKey() throws NoSuchAlgorithmException{
			Key key;
			SecureRandom rand = new SecureRandom();
			KeyGenerator generator = null;
			try {
				generator = KeyGenerator.getInstance("AES","BC");
			} catch (NoSuchProviderException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			generator.init(rand);
			generator.init(256);
			key = generator.generateKey();
			return key;
		}
		
		public static void storeKey(Key key) throws IOException{
			File file = new File(CryptoUtility.KeyFileName);			
			 String keyEncoded = Base64.encodeBase64String(key.getEncoded());
			    writeStringToFile(file,keyEncoded);
		}
		
		public static Key loadKey() 
		{
			File file = new File(CryptoUtility.KeyFileName);
		    String data = null;
		    byte[] encoded = null;
			try {
				data = new String(readFileToByteArray(file));
				encoded =  Base64.decodeBase64(data);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}	   
		    return new SecretKeySpec(encoded, "AES");
		}
		
		public static boolean checkStringStartingwithENC(String inputString){
			if(inputString.startsWith(prefix) && inputString.endsWith(suffix))
			return true;
			else
				return false;
		}
		
		public static String removePrefixAndSuffix(String inputString){
			 return inputString.substring(prefix.length(), inputString.length()-suffix.length());
		}
		 
}
