package com.srikanth.spring.encryption;


public interface BouncycastleCrypto {
	
	public String encrypt(String val);
	public String decrypt(String val);

}
