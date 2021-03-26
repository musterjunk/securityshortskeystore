package com.musterjunk.keystore;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Base64;

import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
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
    	//Security.insertProviderAt(new BouncyCastleProvider(), 1);
    	try {    	
    		String ksName = System.getProperty("user.home") + "/data/keystore.jks";
    		KeyStoreManager ksm = new KeyStoreManager.Builder()
    				.withPassword("somelongpassword")
    				//.withType("BKS") //BC only // does not support probing with key tool, changes password
    				//.withType("PKCS12") //changes password, BC does not support non-private keys
    				//.withType("JKS") //neither supports non-private keys
    				//.withType("BCFKS") //BC only,  keytool probing not supported, changes password
    				//.withType("UBER") //does not support probing with keytool, changes password, BC only
    				.withType("JCEKS") //storing keys with different password changes the keystore password //works with sun
    				//.withType("BCPKCS12") //BC does not support non-private keys, BC only
    				.withStoreFileName(ksName)
    				.build();
    		
    		SecretKey key = ksm.getAESKey("aeskey", "somelongpassword2", true);
    		SecretKey key2 = ksm.getAESKey("aeskey2", "somelongpassword3", true);
    		if(!key.getAlgorithm().equals("AES")) {
    			fail();
    		}
    		
    		String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
			System.out.println("Base64 encoded key is: " + encodedKey);
			encodedKey = Base64.getEncoder().encodeToString(key2.getEncoded());
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
