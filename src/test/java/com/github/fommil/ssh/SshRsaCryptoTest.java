package com.github.fommil.ssh;

import com.google.common.io.Resources;
import org.junit.Test;

import javax.crypto.Cipher;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

import static com.github.fommil.ssh.SshRsaCrypto.RSA;
import static com.google.common.base.Charsets.UTF_8;
import static com.google.common.io.Resources.getResource;
import static org.junit.Assert.assertEquals;

public class SshRsaCryptoTest {

    private byte[] encrypt(String text, PublicKey key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(text.getBytes());
    }

    private String decrypt(byte[] text, PrivateKey key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return new String(cipher.doFinal(text));
    }

    @Test
    public void testEncryptDecrypt() throws Exception {
        String publicKeyBody = Resources.toString(getResource(getClass(), "/test_rsa.pub"), UTF_8);
        String privateKeyBody = Resources.toString(getResource(getClass(), "/test_rsa"), UTF_8);

        SshRsaCrypto rsa = new SshRsaCrypto();
        PublicKey publicKey = rsa.readPublicKey(rsa.slurpPublicKey(publicKeyBody));
        PrivateKey privateKey = rsa.readPrivateKey(rsa.slurpPrivateKey(privateKeyBody));

        String message = "Hello World!!1!";

        byte[] cipherText = encrypt(message, publicKey);
        String decrypted = decrypt(cipherText, privateKey);

        assertEquals(message, decrypted);
    }
}
