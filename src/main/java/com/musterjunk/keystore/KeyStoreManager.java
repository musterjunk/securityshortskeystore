package com.musterjunk.keystore;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.SecretKey;

import com.musterjunk.keys.AESKeys;
import com.musterjunk.keystore.exception.KeyAliasNotFoundException;
import java.security.KeyStore.SecretKeyEntry;

public class KeyStoreManager {
	private String password;
	private String storeFileName;
	private KeyStore store;
	private String type;

	private KeyStoreManager(){
		
	}
	
	public static class Builder {
		private String password;
		private String storeFileName;
		private String type;

		public Builder() {
			
		}
		
		public Builder withPassword(String password) {
			this.password = password;
			return this;
		}
		
		public Builder withStoreFileName(String storeFileName) {
			this.storeFileName = storeFileName;
			return this;
		}
		
		public Builder withType(String type) {
			this.type = type;
			return this;
		}
		
		public KeyStoreManager build() {
			KeyStoreManager manager = new KeyStoreManager();
			manager.password = this.password;
			manager.storeFileName = this.storeFileName;
			manager.type = this.type;
			return manager;
		}
	}
	
	public KeyStore getKeyStore() 
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		KeyStore ks = KeyStore.getInstance(this.type);
		File file = new File(this.storeFileName);
		if (!file.exists()) {
			ks.load(null, this.password.toCharArray());
			FileOutputStream fos = new FileOutputStream(file);
			ks.store(fos, this.password.toCharArray());
			fos.close();
		}
		else {
			FileInputStream fis = new FileInputStream(file);
			ks.load(fis, password.toCharArray());
		}
		this.store = ks;
		return ks;
	}
	
	public SecretKey getAESKey(String alias, String password) 
			throws KeyStoreException, NoSuchAlgorithmException, FileNotFoundException, 
			CertificateException, UnrecoverableEntryException, IOException, 
			KeyAliasNotFoundException {
		
		return this.getAESKey(alias, password, false);
		
	}
	
	public SecretKey getAESKey(String alias, String password, boolean createNewKey) 
			throws KeyStoreException, NoSuchAlgorithmException, FileNotFoundException, 
				CertificateException, IOException, KeyAliasNotFoundException, 
				UnrecoverableEntryException {
		
		if (this.store == null) {
			this.store = this.getKeyStore();
		}
		
		SecretKey sk;
		if (!this.store.containsAlias(alias)) {
			if (createNewKey) {
				sk = AESKeys.getNewAESKey();
				File file = new File(this.storeFileName);
				this.store.setEntry(alias, new KeyStore.SecretKeyEntry(sk), new KeyStore.PasswordProtection(password.toCharArray()));
				FileOutputStream fos = new FileOutputStream(file);
				this.store.store(fos, password.toCharArray());
				fos.close();
			} else {
				throw new KeyAliasNotFoundException(alias);
			}
		} else {
			if(this.store.entryInstanceOf(alias, KeyStore.SecretKeyEntry.class)) {
				SecretKeyEntry entry = (SecretKeyEntry) this.store.getEntry(alias, new KeyStore.PasswordProtection(password.toCharArray()));
				sk = entry.getSecretKey();
			} else throw new KeyStoreException("Alias at: " + alias + " is not of type SecretKey it is of type: " +
				this.store.getEntry(alias, new KeyStore.PasswordProtection(password.toCharArray())).getClass() );
		}
		
		return sk;
	}
	
	public void createKeyStoreWithAESKey(String alias, String keyStoreFileName, String password) 
			throws NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
		
		KeyStore ks = KeyStore.getInstance(this.type);
		File file = new File(keyStoreFileName);
		if (!file.exists()) {
			ks.load(null, password.toCharArray());
			FileOutputStream fos = new FileOutputStream(file);
			ks.store(fos, password.toCharArray());
			fos.close();
		}
		else {
			FileInputStream fis = new FileInputStream(file);
			ks.load(fis, password.toCharArray());
			fis.close();
		}
		
		if (!ks.containsAlias(alias)) {
			SecretKey sk = AESKeys.getNewAESKey();
			ks.setEntry(alias, new KeyStore.SecretKeyEntry(sk), new KeyStore.PasswordProtection(password.toCharArray()));
			FileOutputStream fos = new FileOutputStream(file);
			ks.store(fos, password.toCharArray());
			fos.close();
		}
		
	}
}
