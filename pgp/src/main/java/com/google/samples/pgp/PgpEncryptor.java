// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package com.google.samples.pgp;

import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import com.google.common.io.BaseEncoding;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.PublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;

/**
 * PGP encryptor/decryptor.
 * Requires a PgpKeyProvider.
 */
public final class PgpEncryptor {
    private static final Logger LOGGER = LogManager.getLogger(PgpEncryptor.class);
    private static final int BUFFER_SIZE = 1 << 16;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private int hashAlgorithm;
    private boolean asciiArmour;
    private PGPDataEncryptorBuilder dataEncryptorBuilder;
    private KeyProvider<PGPPublicKey, PGPSecretKey, PGPPrivateKey> keyProvider;

    public PgpEncryptor(KeyProvider<PGPPublicKey, PGPSecretKey, PGPPrivateKey> keyProvider) {
        this(keyProvider, PGPUtil.SHA256, SymmetricKeyAlgorithmTags.AES_256);
    }

    public PgpEncryptor(
            KeyProvider<PGPPublicKey, PGPSecretKey, PGPPrivateKey> keyProvider,
            int hashAlgorithm,
            int symmetricKeyAlgorithmTags
    ) {
        LOGGER.debug("Initialising encryptor");
        this.keyProvider = keyProvider;
        this.hashAlgorithm = hashAlgorithm;
        this.dataEncryptorBuilder = new BcPGPDataEncryptorBuilder(symmetricKeyAlgorithmTags)
                .setSecureRandom(new SecureRandom())
                .setWithIntegrityPacket(true);
    }

    /**
     * If set to true, the encryptor will produce ASCII armoured encrypted messages.
     *
     * @param asciiArmour used to switch ASCII armour on and off
     * @return the instance itself
     */
    public PgpEncryptor setAsciiArmour(boolean asciiArmour) {
        this.asciiArmour = asciiArmour;
        return this;
    }

    /**
     * Checks the status of the ASCII armouring feature. True for enabled, false for disabled.
     *
     * @return whether or not ASCII armour is enabled.
     */
    public boolean isAsciiArmour() {
        return this.asciiArmour;
    }

    /**
     * Produces a cipher text that is encrypted with all the public keys in the PgpKeyProvider
     * keyring and signs with all the secret keys in the PgpKeyProvider keyring.
     *
     * @param plainText the plain text to encrypt
     * @return the signed cipher text
     * @throws PgpEncryptionException if the encryption fails
     */
    public String encrypt(String plainText) throws PgpEncryptionException {
        List<PGPPublicKey> encryptionKeys = this.keyProvider.getPublicKeys();
        List<PGPSecretKey> signingKeys = this.keyProvider.getSecretKeys();
        return encrypt(plainText, encryptionKeys, signingKeys);
    }

    /**
     * Produces cipher text that is encrypted with the public keys belonging to all the recipients
     * and signs the message with the private keys of all the senders.
     *
     *
     * @param plainText the plain text to encrypt
     * @param senders a string array with the user identifiers of the senders
     * @param recipients a string array with the user identifiers of the recipients
     * @return the signed cipher text
     * @throws PgpEncryptionException if the encryption fails
     */
    public String encrypt(String plainText, String[] senders, String[] recipients)
        throws PgpEncryptionException {
        List<PGPPublicKey> encryptionKeys = this.keyProvider.getPublicKeys(recipients);
        List<PGPSecretKey> signingKeys = this.keyProvider.getSecretKeys(senders);
        return encrypt(plainText, encryptionKeys, signingKeys);
    }

    private String encrypt(
            String plainText, List<PGPPublicKey> encryptionKeys, List<PGPSecretKey> signingKeys
    ) throws PgpEncryptionException {
        try (InputStream input =
                     new ByteArrayInputStream(plainText.getBytes(StandardCharsets.UTF_8))) {
            byte[] output = encrypt(input, encryptionKeys, signingKeys);

            if (this.asciiArmour) {
                return new String(output, StandardCharsets.UTF_8);
            }

            return BaseEncoding.base64Url().encode(output);
        } catch (IOException exception) {
            throw new PgpEncryptionException("Plain text reading error", exception);
        }
    }

    private byte[] encrypt(
        InputStream inputStream, List<PGPPublicKey> encryptionKeys, List<PGPSecretKey> signingKeys
    ) throws PgpEncryptionException {
        LOGGER.debug("Encryption keys: \n" + serialisePublicKeys(encryptionKeys));
        LOGGER.debug("Signing keys: \n" + serialiseSecretKeys(signingKeys));

        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            if (this.asciiArmour) {
                writeArmoredCipherText(inputStream, outputStream, encryptionKeys, signingKeys);
            } else {
                writeCipherText(inputStream, outputStream, encryptionKeys, signingKeys);
            }

            return outputStream.toByteArray();
        } catch (IllegalStateException | IOException | PGPException exception) {
            throw new PgpEncryptionException("Cipher text writing error", exception);
        }
    }

    private void writeArmoredCipherText(
            InputStream inputStream,
            OutputStream outputStream,
            List<PGPPublicKey> encryptionKeys,
            List<PGPSecretKey> signingKeys
    ) throws IOException, PGPException {
        LOGGER.debug("Encrypting with ASCII armour");

        try (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream)) {
            writeCipherText(inputStream, armoredOutputStream, encryptionKeys, signingKeys);
        }
    }

    private void writeCipherText(
            InputStream inputStream,
            OutputStream outputStream,
            List<PGPPublicKey> encryptionKeys,
            List<PGPSecretKey> signingKeys
    ) throws IOException, PGPException {
        // Create data generator and prepare it to encrypt with all the public keys
        PGPEncryptedDataGenerator dataGenerator = createDataGenerator(encryptionKeys);
        // Create encrypted output and write
        try (OutputStream encryptedOutputStream =
                     dataGenerator.open(outputStream, new byte[BUFFER_SIZE])) {
            writeToEncryptedOutput(inputStream, encryptedOutputStream, signingKeys);
        }

        dataGenerator.close();
    }

    private PGPEncryptedDataGenerator createDataGenerator(List<PGPPublicKey>  encryptionKeys) {
        PGPEncryptedDataGenerator dataGenerator =
                new PGPEncryptedDataGenerator(this.dataEncryptorBuilder);

        for (PGPPublicKey publicKey : encryptionKeys) {
            PublicKeyKeyEncryptionMethodGenerator encryptionMethodGenerator =
                    new BcPublicKeyKeyEncryptionMethodGenerator(publicKey);
            dataGenerator.addMethod(encryptionMethodGenerator);
        }

        return dataGenerator;
    }

    private void writeToEncryptedOutput(
            InputStream inputStream,
            OutputStream encryptedOutputStream,
            List<PGPSecretKey> signingKeys
    ) throws IOException, PGPException {
        // Generate compressed data
        PGPCompressedDataGenerator compressedDataGenerator =
                new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
        LOGGER.debug("Initialised compressor");

        try (BCPGOutputStream bcpgOutputStream =
                     new BCPGOutputStream(compressedDataGenerator.open(encryptedOutputStream))) {
            // Create signature generators
            List<PGPSignatureGenerator> signatureGenerators =
                    createSignatureGenerators(signingKeys);
            LOGGER.debug("Created signature generator(s)");

            // Write one-pass signature
            for (PGPSignatureGenerator signatureGenerator : signatureGenerators) {
                PGPOnePassSignature onePassSignature =
                        signatureGenerator.generateOnePassVersion(false);
                onePassSignature.encode(bcpgOutputStream);
            }
            LOGGER.debug("Encoded one-pass signature(s)");

            writeLiteralData(inputStream, bcpgOutputStream, signatureGenerators);
            LOGGER.debug("Wrote literal data");

            // Write signatures
            for (PGPSignatureGenerator signatureGenerator : signatureGenerators) {
                PGPSignature signature = signatureGenerator.generate();
                signature.encode(bcpgOutputStream);
            }
            LOGGER.debug("Encoded signature(s)");
        }

        compressedDataGenerator.close();
    }

    private List<PGPSignatureGenerator> createSignatureGenerators(
            Collection<PGPSecretKey> signingKeys) throws PGPException {
        List<PGPSignatureGenerator> signatureGenerators = new ArrayList<>();

        for (PGPSecretKey signingKey : signingKeys) {
            PGPPublicKey publicKey = signingKey.getPublicKey();
            PGPContentSignerBuilder contentSignerBuilder =
                    new BcPGPContentSignerBuilder(publicKey.getAlgorithm(), this.hashAlgorithm);
            PGPSignatureGenerator signatureGenerator =
                    new PGPSignatureGenerator(contentSignerBuilder);

            Long signingKeyId = signingKey.getKeyID();
            PGPPrivateKey privateKey =
                this.keyProvider.getPrivateKey(signingKeyId)
                .orElseThrow(() -> new PgpEncryptionException("Unknown key: " + signingKeyId));

            signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);

            for (String userId : Sets.newHashSet(publicKey.getUserIDs())) {
                PGPSignatureSubpacketGenerator subpacketGenerator =
                        new PGPSignatureSubpacketGenerator();
                subpacketGenerator.setSignerUserID(false, userId);
                signatureGenerator.setHashedSubpackets(subpacketGenerator.generate());
            }

            signatureGenerators.add(signatureGenerator);
        }

        return signatureGenerators;
    }

    private void writeLiteralData(
            InputStream inputStream,
            OutputStream outputStream,
            List<PGPSignatureGenerator> signatureGenerators
    ) throws IOException {
        // Create literal data generator
        PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
        // Write literal data and encode signatures
        try (OutputStream literalOutputStream =
                     literalDataGenerator.open(
                             outputStream,
                             PGPLiteralData.UTF8,
                             PGPLiteralData.CONSOLE,
                             PGPLiteralData.NOW,
                             new byte[BUFFER_SIZE])) {
            // Read the input stream and encrypt
            byte[] readingBuffer = new byte[BUFFER_SIZE];
            int readBytes;

            while ((readBytes = inputStream.read(readingBuffer)) >= 0) {
                literalOutputStream.write(readingBuffer, 0, readBytes);

                for (PGPSignatureGenerator signatureGenerator : signatureGenerators) {
                    signatureGenerator.update(readingBuffer, 0, readBytes);
                }
            }
        }
        literalDataGenerator.close();
    }

    /**
     * Produces the decrypted plain text of a cipher text.
     * All the secret keys of the PgpKeyProvider will be tested to try to decrypt the cipher text
     * until one works. All the public keys of the PgpKeyProvider will be tested to try to verify
     * the signature until one works.
     *
     * @param cipherText the cipher text to decrypt
     * @return the plain text
     * @throws PgpDecryptionException if the decryption fails
     */
    public String decrypt(String cipherText) throws PgpDecryptionException {
        List<PGPSecretKey> decryptionKeys = this.keyProvider.getSecretKeys();
        List<PGPPublicKey> verifyingKeys = this.keyProvider.getPublicKeys();
        return decrypt(cipherText, verifyingKeys, decryptionKeys);
    }

    /**
     * Produces the decrypted plain text of a cipher text.
     * The secret key of all of the recipients will be used to decrypt the cipher text until one
     * works. The public keys of all of the senders will be used to verify the signature until one
     * works.
     *
     * @param cipherText the cipher text to decrypt
     * @param senders a string array with the user identifiers of the senders
     * @param recipients a string array with the user identifiers of the recipients
     * @return the plain text
     * @throws PgpDecryptionException if the decryption fails
     */
    public String decrypt(String cipherText, String[] senders, String[] recipients)
        throws PgpDecryptionException {
        List<PGPSecretKey> decryptionKeys = this.keyProvider.getSecretKeys(recipients);
        List<PGPPublicKey> verifyingKeys = this.keyProvider.getPublicKeys(senders);
        return decrypt(cipherText, verifyingKeys, decryptionKeys);
    }

    private String decrypt(
        String cipherText, List<PGPPublicKey> verifyingKeys, List<PGPSecretKey> decryptionKeys
    ) throws PgpDecryptionException {
        InputStream inputStream =
                new ByteArrayInputStream(BaseEncoding.base64Url().decode(cipherText));
        byte[] plainText = decrypt(inputStream, verifyingKeys, decryptionKeys);
        return new String(plainText, StandardCharsets.UTF_8);
    }

    private byte[] decrypt(
        InputStream inputStream, List<PGPPublicKey> verifyingKeys, List<PGPSecretKey> decryptionKeys
    ) throws PgpDecryptionException {
        LOGGER.debug("Verifying keys: \n" + serialisePublicKeys(verifyingKeys));
        LOGGER.debug("Decryption keys: \n" + serialiseSecretKeys(decryptionKeys));

        try {
            InputStream decodedInputStream = PGPUtil.getDecoderStream(inputStream);
            PGPObjectFactory pgpObjectFactory = new BcPGPObjectFactory(decodedInputStream);
            Optional<PGPOnePassSignature> possibleOnePassSignature = Optional.empty();
            PGPPublicKeyEncryptedData publicKeyEncryptedData = null;
            boolean signatureVerified = false;
            byte[] plainText = null;

            Object pgpObject;

            while ((pgpObject = pgpObjectFactory.nextObject()) != null) {
                if (pgpObject instanceof PGPEncryptedDataList) {
                    LOGGER.debug("Finding decryptable data");
                    publicKeyEncryptedData =
                            getDecryptablePublicKeyData(
                                    (PGPEncryptedDataList) pgpObject, decryptionKeys
                            );
                    PGPPrivateKey decryptionKey =
                            findDecryptionKey(publicKeyEncryptedData, decryptionKeys).get();
                    InputStream decryptedDataStream =
                            publicKeyEncryptedData.getDataStream(
                                    new BcPublicKeyDataDecryptorFactory(decryptionKey)
                            );
                    pgpObjectFactory = new BcPGPObjectFactory(decryptedDataStream);
                } else if (pgpObject instanceof PGPCompressedData) {
                    LOGGER.debug("Decompressing data");
                    PGPCompressedData compressedData = (PGPCompressedData) pgpObject;
                    pgpObjectFactory = new BcPGPObjectFactory(compressedData.getDataStream());
                } else if (pgpObject instanceof PGPOnePassSignatureList) {
                    LOGGER.debug("Finding verifiable one-pass signature");
                    possibleOnePassSignature =
                            getVerifiableOnePassSignature(
                                    (PGPOnePassSignatureList) pgpObject, verifyingKeys
                            );
                } else if (pgpObject instanceof PGPLiteralData) {
                    LOGGER.debug("Reading literal data");
                    PGPOnePassSignature onePassSignature = possibleOnePassSignature.orElseThrow(
                            () -> new PgpDecryptionException("No one pass signature present.")
                    );
                    plainText = readLiteralData((PGPLiteralData) pgpObject, onePassSignature);
                } else if (pgpObject instanceof PGPSignatureList) {
                    LOGGER.debug("Verifying signature");
                    PGPOnePassSignature onePassSignature = possibleOnePassSignature.orElseThrow(
                            () -> new PgpDecryptionException("No one pass signature present.")
                    );
                    signatureVerified =
                            verifyAnySignature((PGPSignatureList) pgpObject, onePassSignature);
                }
            }

            if (publicKeyEncryptedData == null) {
                throw new PgpDecryptionException("Failed to decrypt the message");
            }
            if (publicKeyEncryptedData.isIntegrityProtected() && !publicKeyEncryptedData.verify()) {
                throw new PgpDecryptionException("Message failed integrity check");
            }
            if (!signatureVerified) {
                throw new PgpDecryptionException("Signature not verified");
            }

            return plainText;
        } catch (IOException | PGPException exception) {
            throw new PgpDecryptionException("Cipher text reading error", exception);
        }
    }

    private String serialiseSecretKeys(List<PGPSecretKey> keys) {
        StringBuilder builder = new StringBuilder();

        for (PGPSecretKey key : keys) {
            builder.append(
                    String.format(
                            "Key ID [%s] User[%s]\n",
                            Long.toHexString(key.getKeyID()),
                            Lists.newArrayList(key.getUserIDs())
                    )
            );
        }

        return builder.toString();
    }

    private String serialisePublicKeys(List<PGPPublicKey> keys) {
        StringBuilder builder = new StringBuilder();

        for (PGPPublicKey key : keys) {
            builder.append(
                    String.format(
                            "Key ID [%s] User[%s]\n",
                            Long.toHexString(key.getKeyID()),
                            Lists.newArrayList(key.getUserIDs())
                    )
            );
        }

        return builder.toString();
    }

    private PGPPublicKeyEncryptedData getDecryptablePublicKeyData(
            PGPEncryptedDataList encryptedDataList, List<PGPSecretKey> decryptionKeys
    ) throws PgpDecryptionException {
        return Lists.newArrayList(encryptedDataList.getEncryptedDataObjects())
                .stream()
                .filter(data -> data instanceof PGPPublicKeyEncryptedData)
                .map(data -> (PGPPublicKeyEncryptedData) data)
                .peek(data -> LOGGER.debug("Data encrypted with key: " + Long.toHexString(data.getKeyID())))
                .filter(data -> decryptionKeyExists(data, decryptionKeys))
                .peek(data -> LOGGER.debug(
                        "Decryptable data found. Encrypted with public key: " +  Long.toHexString(data.getKeyID())
                        )
                )
                .findAny()
                .orElseThrow(() -> new PgpDecryptionException("Data stream is not decryptable"));
    }

    private boolean decryptionKeyExists(
            PGPPublicKeyEncryptedData publicKeyEncryptedData, List<PGPSecretKey> decryptionKeys
    ) {
        return decryptionKeys.stream()
                .anyMatch(key -> {
                    PGPPublicKey publicKey = key.getPublicKey();
                    return publicKey.getKeyID() == publicKeyEncryptedData.getKeyID();
                });
    }

    private Optional<PGPPrivateKey> findDecryptionKey(
            PGPPublicKeyEncryptedData publicKeyEncryptedData, List<PGPSecretKey> decryptionKeys
    ) {

        return decryptionKeys.stream()
            .filter(key -> {
              PGPPublicKey publicKey = key.getPublicKey();
              boolean privateKeyExists = this.keyProvider.getPrivateKey(key.getKeyID())
                      .isPresent();
              return publicKey.getKeyID() == publicKeyEncryptedData.getKeyID() && privateKeyExists;
            })
            .map(key -> this.keyProvider.getPrivateKey(key.getKeyID()).get())
            .peek(key -> LOGGER.debug("Found decryption key: " + Long.toHexString(key.getKeyID())))
            .findAny();
    }

    private Optional<PGPOnePassSignature> getVerifiableOnePassSignature(
            PGPOnePassSignatureList onePassSignatures, List<PGPPublicKey> signatureVerifyingKeys
    ) throws PGPException {
        for (PGPOnePassSignature onePassSignature : onePassSignatures) {
            long signatureKeyId = onePassSignature.getKeyID();

            Optional<PGPPublicKey> possibleVerifyingKey = signatureVerifyingKeys.stream()
                    .filter(key -> key.getKeyID() == signatureKeyId)
                    .peek(key -> LOGGER.debug("One-pass signature matches key: " + Long.toHexString(key.getKeyID())))
                    .findAny();

            if (possibleVerifyingKey.isPresent()) {
                PGPPublicKey verifyingKey = possibleVerifyingKey.get();
                onePassSignature.init(new BcPGPContentVerifierBuilderProvider(), verifyingKey);
                return Optional.of(onePassSignature);
            }
        }

        return Optional.empty();
    }

    private byte[] readLiteralData(PGPLiteralData literalData, PGPOnePassSignature onePassSignature)
            throws IOException {
        ByteArrayOutputStream plainText = new ByteArrayOutputStream();
        InputStream dataStream = literalData.getDataStream();

        byte[] buffer = new byte[BUFFER_SIZE];
        int readBytes;

        while ((readBytes = dataStream.read(buffer)) >= 0) {
            onePassSignature.update(buffer, 0, readBytes);
            plainText.write(buffer, 0, readBytes);
        }

        return plainText.toByteArray();
    }

    private boolean verifyAnySignature(
            PGPSignatureList signatures, PGPOnePassSignature onePassSignature
    ) throws PGPException {
        Optional<PGPSignature> possibleSignature = Lists.newArrayList(signatures)
                .stream()
                .filter(signature -> signature.getKeyID() == onePassSignature.getKeyID())
                .peek(signature ->
                        LOGGER.debug("One-pass matched signature of key: " + Long.toHexString(signature.getKeyID()))
                )
                .findAny();

        PGPSignature signature = possibleSignature.orElseThrow(
                () -> new PgpDecryptionException("No matching signature present"));
        return onePassSignature.verify(signature);
    }

    /**
     * Custom exception for any encryption errors.
     */
    public static final class PgpEncryptionException extends PgpException {
        public PgpEncryptionException(String message, Exception innerException) {
            super(message, innerException);
        }

        public PgpEncryptionException(String message) {
            super(message);
        }
    }

    /**
     * Custom exception for any decryption errors.
     */
    public static final class PgpDecryptionException extends PgpException {
        public PgpDecryptionException(String message, Exception innerException) {
            super(message, innerException);
        }

        public PgpDecryptionException(String message) {
            super(message);
        }
    }
}
