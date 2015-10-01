package org.jolokia.jvmagent.security;/*
 * 
 * Copyright 2015 Roland Huss
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Enumeration;

import org.testng.annotations.Test;

import static org.testng.Assert.*;

/**
 * @author roland
 * @since 01/10/15
 */
public class KeyStoreUtilTest {

    public static final String CA_CERT_SUBJECT_DN = "CN=ca.test.jolokia.org, C=DE, ST=Bavaria, L=Pegnitz, EMAILADDRESS=roland@jolokia.org, OU=Dev, O=Jolokia";
    public static final String SERVER_CERT_SUBJECT_DN = "CN=jolokia-test.org, OU=Dev, O=Jolokia, ST=Bavaria, C=DE";

    public static final String CA_ALIAS = "cn=ca.test.jolokia.org,c=de,st=bavaria,l=pegnitz,1.2.840.113549.1.9.1=#1612726f6c616e64406a6f6c6f6b69612e6f7267,ou=dev,o=jolokia";
    public static final String SERVER_ALIAS = "cn=jolokia-test.org,ou=dev,o=jolokia,st=bavaria,c=de";

    @Test
    public void testTrustStore() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        File caPem = getTempFile("cacert.pem");
        KeyStore keystore = createKeyStore();

        KeyStoreUtil.updateWithCaPem(keystore, caPem);

        Enumeration<String> aliases = keystore.aliases();
        String alias = aliases.nextElement();
        assertFalse(aliases.hasMoreElements());
        assertTrue(alias.contains("ca.test.jolokia.org"));
        X509Certificate cert = (X509Certificate) keystore.getCertificate(alias);
        cert.checkValidity();
        assertEquals(cert.getSubjectDN().getName(), CA_CERT_SUBJECT_DN);
        RSAPublicKey key = (RSAPublicKey) cert.getPublicKey();
        assertEquals(key.getAlgorithm(),"RSA");
    }

    @Test
    public void testKeyStore() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, InvalidKeySpecException, UnrecoverableKeyException {
        File serverPem = getTempFile("servercert.pem");
        File keyPem = getTempFile("serverkey.pem");
        KeyStore keystore = createKeyStore();

        KeyStoreUtil.updateWithServerPems(keystore, serverPem, keyPem, "RSA", new char[0]);

        Enumeration<String> aliases = keystore.aliases();
        String alias = aliases.nextElement();
        assertFalse(aliases.hasMoreElements());

        assertTrue(alias.contains("jolokia-test.org"));

        X509Certificate cert = (X509Certificate) keystore.getCertificate(alias);
        cert.checkValidity();
        assertEquals(cert.getSubjectDN().getName(), SERVER_CERT_SUBJECT_DN);
        RSAPrivateCrtKey key = (RSAPrivateCrtKey) keystore.getKey(alias, new char[0]);
        assertEquals("RSA",key.getAlgorithm());
        RSAPublicKey pubKey = (RSAPublicKey) cert.getPublicKey();
        assertEquals("RSA",pubKey.getAlgorithm());
    }

    @Test
    public void testBoth() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, InvalidKeySpecException, InvalidKeyException, NoSuchProviderException, SignatureException {
        File caPem = getTempFile("cacert.pem");
        File serverPem = getTempFile("servercert.pem");
        File keyPem = getTempFile("serverkey.pem");

        KeyStore keystore = createKeyStore();
        KeyStoreUtil.updateWithCaPem(keystore, caPem);
        KeyStoreUtil.updateWithServerPems(keystore, serverPem, keyPem, "RSA", new char[0]);

        X509Certificate caCert = (X509Certificate) keystore.getCertificate(CA_ALIAS);
        X509Certificate serverCert = (X509Certificate) keystore.getCertificate(SERVER_ALIAS);

        // Check that server cert is signed by ca
        serverCert.verify(caCert.getPublicKey());
    }

    @Test
    public void testInvalid() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, InvalidKeySpecException {

        for (String file : new String[]{"invalid_base64.pem", "invalid_begin.pem", "invalid_end.pem"}) {
            File invalidPem = getTempFile(file);

            KeyStore keystore = createKeyStore();
            try {
                KeyStoreUtil.updateWithCaPem(keystore, invalidPem);
                fail();
            } catch (Exception exp) {
            }
            try {
                KeyStoreUtil.updateWithServerPems(keystore, getTempFile("servercert.pem"), invalidPem, "RSA", new char[0]);
                fail();
            } catch (Exception exp) {
            }
        }
    }

    @Test
    public void testMissingBegin() throws IOException {
        File invalidPem = getTempFile("invalid_begin.pem");


    }

    // ========================================================

    private KeyStore createKeyStore() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(null);
        return keystore;
    }

    private File getTempFile(String path) throws IOException {
        InputStream is = this.getClass().getResourceAsStream("/certs/" + path);
        File dest = File.createTempFile("cert-", "pem");
        LineNumberReader reader = new LineNumberReader(new InputStreamReader(is));
        FileWriter writer = new FileWriter(dest);
        try {
            String line;
            while ((line = reader.readLine()) != null) {
                writer.write(line + "\n");
            }
            return dest;
        } finally {
            writer.close();
            reader.close();
        }
    }
}
