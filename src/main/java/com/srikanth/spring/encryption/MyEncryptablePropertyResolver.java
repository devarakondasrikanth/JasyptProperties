package com.srikanth.spring.encryption;

import org.jasypt.encryption.StringEncryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;


@Component
public class MyEncryptablePropertyResolver implements EncryptablePropertyResolver {
	
	private static final Logger LOG = LoggerFactory.getLogger(MyEncryptablePropertyResolver.class);
	
	@Autowired @Lazy
	private BouncycastleCryptoImpl cryptoService;
	
	@Value("${variable.secret-var}")
	private String secValue;
	
	@Bean("jasyptStringEncryptor") @Lazy
    public StringEncryptor stringEncryptor() {  
		LOG.info("My stringEncryptor called");
        return cryptoService;
    }

	@Override
	public String resolvePropertyValue(String value) {
		LOG.info("ResolvePropertyValue called");
		if(CryptoUtility.checkStringStartingwithENC(value)){
			return cryptoService.decrypt(value);
		}
		return value;
	}

}
