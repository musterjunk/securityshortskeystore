package com.musterjunk.keystore;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.KeyStore.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyStoreBuilderParameters;
import javax.net.ssl.X509ExtendedKeyManager;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import com.musterjunk.keystore.exception.KeyAliasNotFoundException;
import com.musterjunk.keystore.KeyStoreBuilder;

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
    				.withType("PKCS12") //changes password, BC does not support non-private keys
    				//.withType("JKS") //neither supports non-private keys
    				//.withType("BCFKS") //BC only,  keytool probing not supported, changes password
    				//.withType("UBER") //does not support probing with keytool, changes password, BC only
    				//.withType("JCEKS") //storing keys with different password changes the keystore password //works with sun
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
    
    @Test
    public void testWithBuilder() throws GeneralSecurityException, IOException {
        char[] password1 = "password1".toCharArray();
        char[] password2 = "password2".toCharArray();
        Map<String, ProtectionParameter> passwordsMap = new HashMap<>();
        passwordsMap.put("rsaentry", new PasswordProtection(password1));
        passwordsMap.put("dsaentry", new PasswordProtection(password2));
     
        KeyStore keyStore = generateStore();
        KeyStore.Builder builder = new KeyStoreBuilder(() -> keyStore, alias -> {
            // alias is lowercased keystore alias with prefixed numbers :-/
            // parse the alias
            int firstDot = alias.indexOf('.');
            int secondDot = alias.indexOf('.', firstDot + 1);
            if ((firstDot == -1) || (secondDot == firstDot)) {
                // invalid alias
                return null;
            }
            String keyStoreAlias = alias.substring(secondDot + 1);
            return passwordsMap.get(keyStoreAlias);
        });
     
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("NewSunX509");
        kmf.init(new KeyStoreBuilderParameters(builder));
        X509ExtendedKeyManager keyManager = (X509ExtendedKeyManager) kmf.getKeyManagers()[0];
     
        String rsaAlias = keyManager.chooseServerAlias("RSA", null, null);
        assertTrue((rsaAlias).contains("rsaentry"));
        PrivateKey rsaPrivateKey = keyManager.getPrivateKey(rsaAlias);
        assertTrue((rsaPrivateKey) != null); // can get password
     
        String dsaAlias = keyManager.chooseServerAlias("DSA", null, null);
        assertTrue((dsaAlias).contains("dsaentry"));
        PrivateKey dsaPrivateKey = keyManager.getPrivateKey(dsaAlias);
        assertTrue((dsaPrivateKey) != null); // can get password
    }

    public static KeyStore generateStore() {
    	try {
			KeyStore ks = KeyStore.getInstance("PKCS12");
			return ks;
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
    }

}
