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
import java.security.cert.Certificate;
import java.security.spec.*;

import org.jolokia.util.Base64Util;

/**
 * Utility class for handling keystores
 *
 * @author roland
 * @since 30/09/15
 */
public class KeyStoreUtil {

    private KeyStoreUtil() {
    }

    /**
     * Update a keystore with a CA certificate
     *
     * @param pTrustStore the keystore to update
     * @param pCaCert     CA cert as PEM used for the trust store
     */
    public static void updateWithCaPem(KeyStore pTrustStore, File pCaCert)
            throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        InputStream is = new FileInputStream(pCaCert);
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X509");
            X509Certificate cert = (X509Certificate) certFactory.generateCertificate(is);

            String alias = cert.getSubjectX500Principal().getName();
            pTrustStore.setCertificateEntry(alias, cert);
        } finally {
            is.close();
        }
    }

    /**
     * Update a key store with the keys found in a server PEM and its key file.
     *
     * @param pKeyStore   keystore to update
     * @param pServerCert server certificate
     * @param pServerKey  server key
     * @param pKeyAlgo    algorithm used in the keystore (e.g. "RSA")
     * @param pPassword   password to use for the key file. must not be null, use <code>char[0]</code>
     *                    for an empty password.
     */
    public static void updateWithServerPems(KeyStore pKeyStore, File pServerCert, File pServerKey, String pKeyAlgo, char[] pPassword)
            throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, KeyStoreException {
        InputStream is = new FileInputStream(pServerCert);
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X509");
            X509Certificate cert = (X509Certificate) certFactory.generateCertificate(is);

            byte[] keyBytes = decodePem(pServerKey);
            PrivateKey privateKey;

            KeyFactory keyFactory = KeyFactory.getInstance(pKeyAlgo);
            try {
                // First let's try PKCS8
                privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
            } catch (InvalidKeySpecException e) {
                // Otherwise try PKCS1
                RSAPrivateCrtKeySpec keySpec = PKCS1Util.decodePKCS1(keyBytes);
                privateKey = keyFactory.generatePrivate(keySpec);
            }

            String alias = cert.getSubjectX500Principal().getName();
            pKeyStore.setKeyEntry(alias, privateKey, pPassword, new Certificate[]{cert});
        } finally {
            is.close();
        }
    }

    // This method is enspired and partly taken from
    // http://oauth.googlecode.com/svn/code/java/
    // All credits to belong to them.
    private static byte[] decodePem(File pemFile) throws IOException {
        BufferedReader reader = new BufferedReader(new FileReader(pemFile));
        try {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("-----BEGIN ")) {
                    return readBytes(pemFile, reader, line.trim().replace("BEGIN", "END"));
                }
            }
            throw new IOException("PEM " + pemFile + " is invalid: no begin marker");
        } finally {
            reader.close();
        }
    }

    private static byte[] readBytes(File pemFile, BufferedReader reader, String endMarker) throws IOException {
        String line;
        StringBuffer buf = new StringBuffer();

        while ((line = reader.readLine()) != null) {
            if (line.indexOf(endMarker) != -1) {
                return Base64Util.decode(buf.toString());
            }
            buf.append(line.trim());
        }
        throw new IOException(pemFile + " is invalid : No end marker");
    }
}

