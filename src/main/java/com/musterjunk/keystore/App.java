package com.musterjunk.keystore;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args )
    {
    	String password = "AReallyLongPassword";
    	if(args.length > 1) {
    		password = args[1];
    	}
    	
        KeyStoreManager ksm = new KeyStoreManager();
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
