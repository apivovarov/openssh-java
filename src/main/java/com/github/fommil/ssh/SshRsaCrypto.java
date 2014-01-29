package com.github.fommil.ssh;

import com.google.common.io.CharStreams;
import com.google.common.io.LineProcessor;
import lombok.Cleanup;
import org.apache.commons.codec.binary.Base64;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import static com.google.common.base.Preconditions.checkArgument;
import static java.security.KeyFactory.getInstance;

/**
 * Helper methods for using OpenSSH RSA private ({@code ~/.ssh/id_rsa})
 * and public ({@code ~/.ssh/id_rsa.pub}) keys to perform encryption
 * and decryption of Strings within the J2SE crypto framework.
 */
public class SshRsaCrypto {

    public static final String RSA = "RSA";

    // http://msdn.microsoft.com/en-us/library/windows/desktop/bb540806%28v=vs.85%29.aspx
    private BigInteger readAsnInteger(DataInputStream in) throws IOException {
        checkArgument(in.read() == 2, "no INTEGER marker");
        int length = in.read();
        if (length >= 0x80) {
            byte[] extended = new byte[length & 0x7f];
            in.readFully(extended);
            length = new BigInteger(extended).intValue();
        }
        byte[] data = new byte[length];
        in.readFully(data);
        return new BigInteger(data);
    }

    public PrivateKey readPrivateKey(byte[] bytes) throws GeneralSecurityException, IOException {
    /*
     Key in the following ASN.1 DER encoding,
     RSAPrivateKey ::= SEQUENCE {
       version           Version,
       modulus           INTEGER,  -- n
       publicExponent    INTEGER,  -- e
       privateExponent   INTEGER,  -- d
       prime1            INTEGER,  -- p
       prime2            INTEGER,  -- q
       exponent1         INTEGER,  -- d mod (p-1)
       exponent2         INTEGER,  -- d mod (q-1)
       coefficient       INTEGER,  -- (inverse of q) mod p
       otherPrimeInfos   OtherPrimeInfos OPTIONAL
     }
   */
        @Cleanup
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes));
        try {
            checkArgument(in.read() == 48, "no id_rsa SEQUENCE");
            checkArgument(in.read() == 130, "no Version marker");
            in.skipBytes(5);

            BigInteger n = readAsnInteger(in);
            readAsnInteger(in);
            BigInteger e = readAsnInteger(in);

            RSAPrivateKeySpec spec = new RSAPrivateKeySpec(n, e);
            return getInstance(RSA).generatePrivate(spec);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

    public PublicKey readPublicKey(byte[] bytes) throws GeneralSecurityException, IOException {
        // http://stackoverflow.com/questions/12749858
        // http://tools.ietf.org/html/rfc4716
        // http://tools.ietf.org/html/rfc4251
        @Cleanup
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes));
        try {
            byte[] sshRsa = new byte[in.readInt()];
            in.readFully(sshRsa);
            checkArgument(new String(sshRsa).equals("ssh-rsa"), "no RFC-4716 ssh-rsa");
            byte[] exp = new byte[in.readInt()];
            in.readFully(exp);
            byte[] mod = new byte[in.readInt()];
            in.readFully(mod);

            BigInteger e = new BigInteger(exp);
            BigInteger n = new BigInteger(mod);
            RSAPublicKeySpec spec = new RSAPublicKeySpec(n, e);
            return getInstance(RSA).generatePublic(spec);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

    /**
     * @param body of {@code ~/.ssh/id_rsa}
     * @return binary form suitable for use in {@link #readPrivateKey(byte[])}
     * @throws IOException
     */
    public byte[] slurpPrivateKey(String body) throws IOException {
        String ascii = CharStreams.readLines(new StringReader(body), new LineProcessor<String>() {
            StringBuilder builder = new StringBuilder();

            @Override
            public boolean processLine(String line) throws IOException {
                if (!(line.contains("-") || line.contains(":"))) {
                    builder.append(line);
                    builder.append("\n");
                }
                return true;
            }

            @Override
            public String getResult() {
                return builder.toString();
            }
        });
        Base64 b64 = new Base64();
        return b64.decode(ascii);
    }

    /**
     * @param body of a single entry {@code ~/.ssh/id_rsa.pub}
     * @return binary form suitable for use in {@link #readPublicKey(byte[])}
     * @throws IOException
     */
    public byte[] slurpPublicKey(String body) throws IOException {
        String[] contents = body.split(" ");
        checkArgument(contents.length == 3, "not a valid id_rsa.pub");
        Base64 b64 = new Base64();
        return b64.decode(contents[1]);
    }
}