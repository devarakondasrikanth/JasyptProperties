package com.srikanth.spring.encryption;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ulisesbocchio.jasyptspringboot.annotation.EnableEncryptableProperties;
@Component
@EnableEncryptableProperties
@RestController
public class TestApp {
	@Value("${variable.secret-var}")
	private String secValue;

	@Value("${inputString}")
	private String orgText;

	private static final Logger LOG = LoggerFactory.getLogger(EncryptionApplication.class);
	 
		@RequestMapping("/getEncryptedValues")
		public String test(){	
			LOG.info("Original text is "+orgText);
			LOG.info("Decrypted text is "+secValue);			
			return secValue;
		}
}
