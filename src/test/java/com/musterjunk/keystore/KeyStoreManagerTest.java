package com.musterjunk.keystore;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Base64;

import javax.crypto.SecretKey;

import org.junit.Test;

import com.musterjunk.keystore.exception.KeyAliasNotFoundException;

/**
 * Unit test for simple App.
 */
public class KeyStoreManagerTest 
{
    /**
     * Rigorous Test :-)
     */
    @Test
    public void shouldAnswerWithTrue()
    {
        assertTrue( true );
    }
    
    //The key store gets created when you call get key if it is not already there
    @Test
    public void createKeyStore() {

    	try {    	
    		String ksName = System.getProperty("user.home") + "/data/keystore.jks";
    		KeyStoreManager ksm = new KeyStoreManager.Builder()
    				.withPassword("somelongpassword")
    				.withStoreFileName(ksName)
    				.build();
    		
    		SecretKey key = ksm.getAESKey("aeskey", true);
    		if(!key.getAlgorithm().equals("AES")) {
    			fail();
    		}
    		
    		String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
			System.out.println("Base64 encoded key is: " + encodedKey);
			
			//ksm.createKeyStoreWithAESKey("ASEKey", ksName, "somelongpassword");
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
		} catch (UnrecoverableEntryException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyAliasNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
}
