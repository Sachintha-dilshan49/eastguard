package eastguard.common;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Loading of PKCS#12 stores and certificates. Error messages name files, never passwords. */
public final class KeyStores {
    public static final String TYPE = "PKCS12";

    private KeyStores() {
    }

    public static KeyStore load(Path file, char[] password) {
        try (InputStream in = Files.newInputStream(file)) {
            KeyStore ks = KeyStore.getInstance(TYPE);
            ks.load(in, password);
            return ks;
        } catch (IOException | GeneralSecurityException e) {
            // A wrong password surfaces as an IOException ("keystore password was incorrect").
            throw new IllegalStateException("cannot load keystore " + file + ": " + e.getMessage(), e);
        }
    }

    /** The alias of the single private-key entry; a store with zero or several key entries is rejected. */
    public static String singleKeyAlias(KeyStore ks, Path file) {
        try {
            List<String> keys = new ArrayList<>();
            for (String alias : Collections.list(ks.aliases())) {
                if (ks.isKeyEntry(alias)) {
                    keys.add(alias);
                }
            }
            if (keys.size() != 1) {
                throw new IllegalStateException(file + " must hold exactly one private key, found " + keys.size());
            }
            return keys.get(0);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("cannot read keystore " + file, e);
        }
    }

    /** Requires at least one trusted certificate and no private keys. */
    public static void requireTrustStore(KeyStore ks, Path file) {
        try {
            int trusted = 0;
            for (String alias : Collections.list(ks.aliases())) {
                if (ks.isKeyEntry(alias)) {
                    throw new IllegalStateException(file + " is a trust store and must not contain private keys");
                }
                if (ks.isCertificateEntry(alias)) {
                    trusted++;
                }
            }
            if (trusted == 0) {
                throw new IllegalStateException(file + " contains no trusted certificates");
            }
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("cannot read trust store " + file, e);
        }
    }

    public static PrivateKey privateKey(KeyStore ks, String alias, char[] password, Path file) {
        try {
            if (ks.getKey(alias, password) instanceof PrivateKey k) {
                return k;
            }
            throw new IllegalStateException(file + ": no private key under alias " + alias);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("cannot read private key " + alias + " from " + file, e);
        }
    }

    public static X509Certificate certificate(KeyStore ks, String alias, Path file) {
        try {
            if (ks.getCertificate(alias) instanceof X509Certificate c) {
                return c;
            }
            throw new IllegalStateException(file + ": no X.509 certificate under alias " + alias);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("cannot read certificate " + alias + " from " + file, e);
        }
    }

    /** Reads one PEM or DER certificate file. */
    public static X509Certificate readCertificate(Path file) {
        try (InputStream in = Files.newInputStream(file)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        } catch (IOException | CertificateException e) {
            throw new IllegalStateException("cannot read certificate " + file, e);
        }
    }

    /** The Ed25519 lease verification key carried by a certificate file (e.g. {@code keys/lease-k1.cer}). */
    public static PublicKey ed25519PublicKey(Path certFile) {
        PublicKey key = readCertificate(certFile).getPublicKey();
        Ed25519.rawPublicKey(key); // throws unless it really is Ed25519
        return key;
    }
}
