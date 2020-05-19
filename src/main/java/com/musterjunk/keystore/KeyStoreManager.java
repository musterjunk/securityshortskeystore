package com.musterjunk.keystore;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.crypto.SecretKey;

import com.musterjunk.keys.AESKeys;

public class KeyStoreManager {

	public KeyStoreManager(){
		
	}
	
	public void createKeyStoreWithAESKey(String alias, String keyStoreFileName, String password) 
			throws NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
		
		KeyStore ks = KeyStore.getInstance("PKCS12");
		File file = new File(keyStoreFileName);
		if (!file.exists()) {
			ks.load(null, password.toCharArray());
			FileOutputStream fos = new FileOutputStream(file);
			ks.store(fos, password.toCharArray());
		}
		else {
			FileInputStream fis = new FileInputStream(file);
			ks.load(fis, password.toCharArray());
		}
		
		if (!ks.containsAlias(alias)) {
			SecretKey sk = AESKeys.getNewAESKey();
			ks.setEntry(alias, new KeyStore.SecretKeyEntry(sk), new KeyStore.PasswordProtection(password.toCharArray()));
			FileOutputStream fos = new FileOutputStream(file);
			ks.store(fos, password.toCharArray());
		}
		
	}
}
