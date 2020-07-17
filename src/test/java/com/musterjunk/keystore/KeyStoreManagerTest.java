package com.musterjunk.keystore;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import org.junit.Test;

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
    
    @Test
    public void createKeyStore() {
    	KeyStoreManager ksm = new KeyStoreManager();
    	String ksName = System.getProperty("user.home") + "/data/keystore.jks";
    	try {
			ksm.createKeyStoreWithAESKey("ASEKey", ksName, "somelongpassword");
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
