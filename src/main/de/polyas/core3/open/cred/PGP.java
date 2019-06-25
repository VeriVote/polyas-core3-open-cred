package de.polyas.core3.open.cred;

import org.bouncycastle.bcpg.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.util.io.Streams;
import java.io.*;
import java.security.*;
import java.util.*;

public class PGP {

    private static final BouncyCastleProvider provider = new BouncyCastleProvider();

    static {
        Security.addProvider(provider);
    }

    static byte[] signAndEncrypt(byte[] message, PGPSecretKey secretKey, String secretPwd,
                                 PGPPublicKey publicKey, boolean armored) throws PGPException {
        try {
            final ByteArrayOutputStream out = new ByteArrayOutputStream();
            final PGPEncryptedDataGenerator encryptedDataGenerator =
                    new PGPEncryptedDataGenerator(
                            (new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256))
                            .setWithIntegrityPacket(true)
                            .setSecureRandom(new SecureRandom()).setProvider(provider)
            );

            encryptedDataGenerator.addMethod(
                (new JcePublicKeyKeyEncryptionMethodGenerator(publicKey))
                .setSecureRandom(new SecureRandom()).setProvider(provider)
            );

            final OutputStream theOut = armored ? new ArmoredOutputStream(out) : out;
            final OutputStream encryptedOut = encryptedDataGenerator.open(theOut, new byte[4096]);

            final PGPCompressedDataGenerator compressedDataGenerator =
                    new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
            final OutputStream compressedOut =
                    compressedDataGenerator.open(encryptedOut, new byte[4096]);
            final PGPPrivateKey privateKey =
                    secretKey.extractPrivateKey(
                            (new JcePBESecretKeyDecryptorBuilder())
                            .setProvider(provider).build(secretPwd.toCharArray())
            );
            final PGPSignatureGenerator signatureGenerator =
                    new PGPSignatureGenerator(
                            (new JcaPGPContentSignerBuilder(
                                    secretKey.getPublicKey().getAlgorithm(),
                                    HashAlgorithmTags.SHA1))
                            .setProvider(provider)
            );
            signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);
            final Iterator<String> it = secretKey.getPublicKey().getUserIDs();
            if (it.hasNext()) {
                final PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
                spGen.setSignerUserID(false, (String) it.next());
                signatureGenerator.setHashedSubpackets(spGen.generate());
            }
            signatureGenerator.generateOnePassVersion(false).encode(compressedOut);
            final PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
            final OutputStream literalOut = literalDataGenerator.open(
                compressedOut, PGPLiteralData.BINARY, "filename",
                new Date(), new byte[4096]
            );
            final ByteArrayInputStream input = new ByteArrayInputStream(message);
            final byte[] buf = new byte[4096];
            int len = input.read(buf);
            while (len > 0) {
                literalOut.write(buf, 0, len);
                signatureGenerator.update(buf, 0, len);
                len = input.read(buf);
            }
            input.close();
            literalDataGenerator.close();
            signatureGenerator.generate().encode(compressedOut);
            compressedDataGenerator.close();
            encryptedDataGenerator.close();
            theOut.close();
            return out.toByteArray();
        } catch (Exception e) {
            throw new PGPException("Error in signAndEncrypt", e);
        }
    }

    byte[] decryptAndVerify(byte[] encryptedMessage, PGPSecretKey secretKey, String secretPwd,
                            PGPPublicKey publicKey) throws PGPException {
        try {
            final Iterator<PGPPublicKeyEncryptedData> it = getEncryptedObjects(encryptedMessage);
            final PGPPublicKeyEncryptedData pbe = it.next();
            final PGPPrivateKey sKey =
                    secretKey.extractPrivateKey(
                            (new JcePBESecretKeyDecryptorBuilder())
                            .setProvider(provider).build(secretPwd.toCharArray())
            );
            final InputStream clear =
                    pbe.getDataStream(
                            (new JcePublicKeyDataDecryptorFactoryBuilder())
                            .setProvider(provider).build(sKey)
                            );

            PGPObjectFactory plainFact =
                    new PGPObjectFactory(clear, new JcaKeyFingerprintCalculator());

            Object message;

            PGPOnePassSignatureList onePassSignatureList = null;
            PGPSignatureList signatureList = null;
            PGPCompressedData compressedData;

            message = plainFact.nextObject();
            final ByteArrayOutputStream actualOutput = new ByteArrayOutputStream();

            while (message != null) {
                if (message instanceof PGPCompressedData) {
                    compressedData = (PGPCompressedData) message;
                    plainFact = new PGPObjectFactory(compressedData.getDataStream(),
                                                     new JcaKeyFingerprintCalculator());
                    message = plainFact.nextObject();
                }

                if (message instanceof PGPLiteralData) {
                    // have to read it and keep it somewhere.
                    Streams.pipeAll(((PGPLiteralData) message).getInputStream(), actualOutput);
                } else if (message instanceof PGPOnePassSignatureList) {
                    onePassSignatureList = (PGPOnePassSignatureList) message;
                } else if (message instanceof PGPSignatureList) {
                    signatureList = (PGPSignatureList) message;
                } else {
                    throw new PGPException("message unknown message type.");
                }
                message = plainFact.nextObject();
            }
            actualOutput.close();
            final byte[] output = actualOutput.toByteArray();

            // verify signature
            if (onePassSignatureList == null || signatureList == null) {
                throw new PGPException("Poor PGP. Signatures not found.");
            } else {

                for (int i = 0; i < onePassSignatureList.size(); i++) {
                    final PGPOnePassSignature ops = onePassSignatureList.get(0);

                    ops.init(
                            (new JcaPGPContentVerifierBuilderProvider())
                                .setProvider(provider),
                            publicKey
                            );
                    ops.update(output);
                    final PGPSignature signature = signatureList.get(i);
                    if (!ops.verify(signature)) {
                        throw new SignatureException("Signature verification failed");
                    }
                }
            }

            if (pbe.isIntegrityProtected() && !pbe.verify()) {
                throw new PGPException("Data is integrity protected but integrity is lost.");
            }

            return actualOutput.toByteArray();
        } catch (Exception e) {
            throw new PGPException("Error in decryptAndVerify", e);
        }

    }

    @SuppressWarnings("unchecked")
    private Iterator<PGPPublicKeyEncryptedData> getEncryptedObjects(byte[] message)
                throws IOException {
        final PGPObjectFactory factory = new PGPObjectFactory(
            PGPUtil.getDecoderStream(new ByteArrayInputStream(message)),
            new JcaKeyFingerprintCalculator()
        );
        final Object first = factory.nextObject();
        final Object list;
        if (first instanceof PGPEncryptedDataList) {
            list = (PGPEncryptedDataList) first;
        } else {
            list = factory.nextObject();
        }
        return (Iterator<PGPPublicKeyEncryptedData>)((PGPEncryptedDataList) list)
                .getEncryptedDataObjects();
    }

    private static PGPSecretKey createSecretKey(PublicKey publicKey, PrivateKey privateKey,
                                                String identity, char[] passPhrase)
                throws IOException, InvalidKeyException, NoSuchProviderException,
                        SignatureException, PGPException {
        final KeyPair pair = new KeyPair(publicKey, privateKey);
        final PGPDigestCalculator sha1Calc =
                (new JcaPGPDigestCalculatorProviderBuilder())
                .build().get(HashAlgorithmTags.SHA1);
        final JcaPGPKeyPair keyPair =
                new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, pair, new Date());
        return new PGPSecretKey(
            PGPSignature.DEFAULT_CERTIFICATION, keyPair, identity, sha1Calc, null, null,
            new JcaPGPContentSignerBuilder(keyPair.getPublicKey().getAlgorithm(),
                                            HashAlgorithmTags.SHA1),
            (new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc))
            .setProvider("BC").build(passPhrase)
        );
    }

    PGPSecretKey createAndExportKey(String pubFilename, String passPhrase,
                                    String authority, boolean armor)
            throws NoSuchAlgorithmException, NoSuchProviderException, FileNotFoundException,
                    IOException, InvalidKeyException, SignatureException, PGPException {
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(4096);
        final KeyPair kp = kpg.generateKeyPair();
        final PGPSecretKey secretKey =
                createSecretKey(kp.getPublic(), kp.getPrivate(), authority,
                                passPhrase.toCharArray());
        OutputStream publicOut = new FileOutputStream(pubFilename);
        if (armor) {
            publicOut = new ArmoredOutputStream(publicOut);
        }

        final PGPPublicKey key = secretKey.getPublicKey();
        key.encode(publicOut);
        publicOut.close();
        return secretKey;
    }

    public static PGPSecretKey createKey(String passPhrase, String authority)
            throws NoSuchAlgorithmException, NoSuchProviderException,
                    InvalidKeyException, SignatureException,
                    PGPException, IOException {
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(4096);
        final KeyPair kp = kpg.generateKeyPair();
        return createSecretKey(kp.getPublic(), kp.getPrivate(), authority,
                                passPhrase.toCharArray());
    }

    public static void exportKey(String pubFilename, PGPSecretKey secretKey,
                                 boolean armor) throws FileNotFoundException, IOException {
        OutputStream publicOut = new FileOutputStream(pubFilename);
        if (armor) {
            publicOut = new ArmoredOutputStream(publicOut);
        }

        final PGPPublicKey key = secretKey.getPublicKey();
        key.encode(publicOut);
        publicOut.close();
    }

    public static void createSignature(String fileName, PGPSecretKey pgpSec,
                                       String outputFileName, char[] pass, boolean armor)
            throws GeneralSecurityException, IOException, PGPException {
        OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFileName));

        if (armor) {
            out = new ArmoredOutputStream(out);
        }

        final PGPPrivateKey pgpPrivKey = pgpSec
            .extractPrivateKey((new JcePBESecretKeyDecryptorBuilder()).setProvider("BC").build(pass));
        final PGPSignatureGenerator sGen = new PGPSignatureGenerator(
            (new JcaPGPContentSignerBuilder(pgpSec.getPublicKey().getAlgorithm(), PGPUtil.SHA1)).setProvider("BC")
        );

        sGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);
        final BCPGOutputStream bOut = new BCPGOutputStream(out);
        final BufferedInputStream fIn = new BufferedInputStream(new FileInputStream(fileName));

        int ch = fIn.read();
        while (ch >= 0) {
            sGen.update(Integer.valueOf(ch).byteValue());
            ch = fIn.read();
        }
        fIn.close();

        sGen.generate().encode(bOut);

        if (armor) {
            out.close();
        }
        out.close();
    }

    public static PGPPublicKey readPublicKey(String fileName) throws IOException, PGPException {
        final BufferedInputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
        final PGPPublicKey pubKey = readPublicKey(keyIn);
        keyIn.close();
        return pubKey;
    }

    /**
     * A simple routine that opens a key ring file and loads the first available key
     * suitable for encryption.
     *
     * @param input
     * data stream containing the public key data
     * @return the first public key found.
     * @throws IOException
     * @throws PGPException
     */
    public static PGPPublicKey readPublicKey(InputStream input) throws IOException, PGPException {
        final PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(
            PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator()
        );

        // we just loop through the collection till we find a key suitable for encryption

        final Iterator<PGPPublicKeyRing> keyRingIter = pgpPub.getKeyRings();
        while (keyRingIter.hasNext()) {
            final PGPPublicKeyRing keyRing = (PGPPublicKeyRing) keyRingIter.next();

            final Iterator<PGPPublicKey> keyIter = keyRing.getPublicKeys();
            while (keyIter.hasNext()) {
                final PGPPublicKey key = (PGPPublicKey) keyIter.next();

                if (key.isEncryptionKey()) {
                    return key;
                }
            }
        }

        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }
}
