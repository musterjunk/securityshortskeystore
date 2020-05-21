package com.musterjunk.keystore;


import static org.junit.Assert.assertTrue;

import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.SecretKey;

import org.junit.Test;

import com.musterjunk.keys.AESKeys;

/**
 * Unit test for simple App.
 */
public class AESKeysTest 
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
    public void verifyAESKey() {
    	try {
			SecretKey key = AESKeys.getNewAESKey();
			System.out.println("Key algorithm is: " + key.getAlgorithm());
			String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
			System.out.println("Base64 encoded key is: " + encodedKey);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
}