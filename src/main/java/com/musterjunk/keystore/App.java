package com.musterjunk.keystore;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.SecretKey;

import com.musterjunk.keystore.exception.KeyAliasNotFoundException;

/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args )
    {
    	String password = "somelongpassword";
    	if(args.length > 0) {
    		password = args[0];
    		System.out.println("Using '" + password + "' as password.");
    	}
    	
        KeyStoreManager ksm = new KeyStoreManager.Builder()
        		.withStoreFileName(System.getProperty("user.home") + "/testData/keystore.jks")
        		.withPassword(password)
        		.build();
        
        try {
			ksm.createKeyStoreWithAESKey("secretAES", System.getProperty("user.home") + "/testData/keystore.jks", password);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
}
