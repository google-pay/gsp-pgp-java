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
import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.bc.BcPGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;

/**
 * The simple key manager is in charge of holding public and secret keys.
 * It can instantiated as a singleton as the methods to alter the internal key
 * chains are synchronised.
 *
 */
public final class PgpKeyManager implements KeyManager,
        KeyProvider<PGPPublicKey, PGPSecretKey, PGPPrivateKey> {
    private static final Logger LOGGER = LogManager.getLogger(PgpKeyManager.class);
    private static volatile PgpKeyManager INSTANCE;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private Map<Long, PGPPrivateKey> privateKeys;
    private PGPSecretKeyRingCollection secretKeyRings;
    private PGPPublicKeyRingCollection publicKeyRings;
    private KeyFingerPrintCalculator keyFingerPrintCalculator;
    private PGPDigestCalculatorProvider digestCalculatorProvider;

    public static PgpKeyManager getInstance() {
        if (INSTANCE == null) {
            synchronized (PgpKeyManager.class) {
                if (INSTANCE == null) {
                    INSTANCE = new PgpKeyManager();
                }
            }
        }

        return INSTANCE;
    }

    private PgpKeyManager() {
        this.privateKeys = new ConcurrentHashMap<>();
        this.keyFingerPrintCalculator = new BcKeyFingerprintCalculator();
        this.digestCalculatorProvider = new BcPGPDigestCalculatorProvider();

        try {
            this.secretKeyRings = new PGPSecretKeyRingCollection(new ArrayList<>());
            this.publicKeyRings = new PGPPublicKeyRingCollection(new ArrayList<>());
        } catch (IllegalArgumentException | IOException | PGPException exception) {
            throw new RuntimeException(exception);
        }
    }

    /**
     * Decodes the input stream in a public key ring collection.
     * Tries to add all the key rings in the collection to the instance key ring collection.
     *
     * @param inputStream an encoded public key ring collection
     * @return A map of the key IDs to the user IDs of the keys
     */
    @Override
    public synchronized Map<Long, Set<String>> addPublicKeys(
            InputStream inputStream
    ) throws KeyManagementException {
        Map<Long, Set<String>> keyUsers = new HashMap<>();

        try {
            InputStream decodedStream = PGPUtil.getDecoderStream(inputStream);
            PGPPublicKeyRingCollection keyRingCollection =
                    new BcPGPPublicKeyRingCollection(decodedStream);
            Lists.newArrayList(keyRingCollection.getKeyRings())
                    .forEach(keyRing -> {
                        List<PGPPublicKey> publicKeys = Lists.newArrayList(keyRing.getPublicKeys());
                        LOGGER.debug(
                                String.format("Reading %d public keys from keyring", publicKeys.size())
                        );

                        for (PGPPublicKey key : publicKeys) {
                            LOGGER.debug("Adding public key: " + key.getKeyID());
                            keyUsers.putIfAbsent(key.getKeyID(), Sets.newHashSet(key.getUserIDs()));
                        }

                        this.publicKeyRings =
                                PGPPublicKeyRingCollection.addPublicKeyRing(
                                        this.publicKeyRings, keyRing
                                );
                    });
        } catch (IllegalArgumentException | IOException | PGPException exception) {
            throw new KeyManagementException("Problem adding PGP public key", exception);
        }

        return keyUsers;
    }

    /**
     * Decodes the input stream in a secret key ring collection.
     * For each key ring, finds the master key. If it is possible to extract the private key from
     * the master key using any of the passphrases, adds the key ring to the instance key ring
     * collection.
     *
     * @param inputStream an encoded private key ring collection
     * @param passphrases an array of passphrases for any of the secret keys in the private key ring
     * collection.
     * @return A map of the key IDs to the user IDs of the keys
     */
    @Override
    public synchronized Map<Long, Set<String>> addSecretKeys(
            InputStream inputStream, char[]... passphrases
    ) throws KeyManagementException {
        Map<Long, Set<String>> keyUsers = new HashMap<>();

        try {
            InputStream decodedStream = PGPUtil.getDecoderStream(inputStream);
            PGPSecretKeyRingCollection keyRingCollection =
                    new PGPSecretKeyRingCollection(decodedStream, this.keyFingerPrintCalculator);
            Lists.newArrayList(keyRingCollection.getKeyRings())
                    .stream()
                    .filter(keyRing -> {
                        Optional<PGPSecretKey> masterKeyMatch = getMasterSecretKey(keyRing);

                        if (masterKeyMatch.isPresent()) {
                            PGPSecretKey masterKey = masterKeyMatch.get();
                            Optional<PGPPrivateKey> privateKeyMatch =
                                    extractPrivateKey(masterKey, passphrases);

                            if (privateKeyMatch.isPresent()) {
                                keyUsers.putIfAbsent(
                                        masterKey.getKeyID(), Sets.newHashSet(masterKey.getUserIDs())
                                );
                                PGPPrivateKey privateKey = privateKeyMatch.get();
                                this.privateKeys.put(masterKey.getKeyID(), privateKey);
                                return true;
                            }
                        }

                        return false;
                    })
                    .forEach(keyRing -> {
                        this.secretKeyRings =
                                PGPSecretKeyRingCollection.addSecretKeyRing(
                                        this.secretKeyRings, keyRing
                                );
                    });
        } catch (IOException | PGPException exception) {
            throw new KeyManagementException("Problem adding PGP secret key", exception);
        }

        return keyUsers;
    }

    private Optional<PGPSecretKey> getMasterSecretKey(PGPSecretKeyRing keyRing) {
        List<PGPSecretKey> secretKeys = Lists.newArrayList(keyRing.getSecretKeys());
        LOGGER.debug(String.format("Keyring contains %d key(s)", secretKeys.size()));

        return secretKeys
                .stream()
                .filter(PGPSecretKey::isMasterKey)
                .peek(key -> LOGGER.debug("Secret master key: " + key.getKeyID()))
                .findAny();
    }

    private Optional<PGPPrivateKey> extractPrivateKey(
            PGPSecretKey secretKey, char[]... passphrases
    ) {
        Optional<PGPPrivateKey> result = Optional.empty();

        for (char[] passphrase : passphrases) {
            PBESecretKeyDecryptor decryptor =
                    new BcPBESecretKeyDecryptorBuilder(this.digestCalculatorProvider)
                            .build(passphrase);
            try {
                PGPPrivateKey privateKey = secretKey.extractPrivateKey(decryptor);
                LOGGER.debug(
                        String.format("Extracted private key %d from secret key %d",
                                privateKey.getKeyID(),
                                secretKey.getKeyID())
                );
                result = Optional.of(privateKey);
                break;
            } catch (PGPException exception) {
                LOGGER.debug(
                        String.format("Private key extraction failed for key: %d. Cause: %s",
                                secretKey.getKeyID(),
                                exception.getMessage())
                );
            }
        }

        if (!result.isPresent()) {
            LOGGER.error(
                    String.format("Tried to extract private key from secret key %d but failed",
                            secretKey.getKeyID()
                    )
            );
        }

        return result;
    }

    /**
     * Returns a list of the public keys corresponding to the user IDs.
     * If no user IDs are passed, all the keys are returned.
     *
     * @param userIds the user IDs of the owners of the keys
     * @return a list of public keys.
     */
    @Override
    public List<PGPPublicKey> getPublicKeys(String... userIds) {
        Predicate<PGPPublicKey> filter = PGPPublicKey::isMasterKey;

        if (userIds != null && userIds.length > 0) {
            Set<String> uniqueUserIds = Sets.newHashSet(userIds);
            Predicate<PGPPublicKey> userFilter = key -> Sets.newHashSet(key.getUserIDs())
                    .stream()
                    .anyMatch(uniqueUserIds::contains);
            filter = filter.and(userFilter);
        }

        return getPublicKeyStream(filter, key -> key)
                .collect(Collectors.toList());
    }

    private <T> Stream<T> getPublicKeyStream(
            Predicate<PGPPublicKey> keyFilter, Function<PGPPublicKey, T> keyMapper
    ) {
        return Lists.newArrayList(this.publicKeyRings.getKeyRings())
                .stream()
                .flatMap(keyRing -> Lists.newArrayList(keyRing.getPublicKeys()).stream())
                .filter(keyFilter)
                .map(keyMapper);
    }

    /**
     * Returns a list of the secret keys corresponding to the user IDs.
     * If no user IDs are passed, all the keys are returned.
     *
     * @param userIds the user IDs of the owners of the keys
     * @return a list of secret keys.
     */
    @Override
    public List<PGPSecretKey> getSecretKeys(String... userIds) {
        Predicate<PGPSecretKey> filter = PGPSecretKey::isMasterKey;

        if (userIds != null && userIds.length > 0) {
            Set<String> uniqueUserIds = Sets.newHashSet(userIds);
            Predicate<PGPSecretKey> userFilter = key -> Sets.newHashSet(key.getUserIDs())
                    .stream()
                    .anyMatch(uniqueUserIds::contains);
            filter = filter.and(userFilter);
        }

        return getSecretKeyStream(filter, key -> key)
                .collect(Collectors.toList());
    }

    private <T> Stream<T> getSecretKeyStream(
            Predicate<PGPSecretKey> keyFilter, Function<PGPSecretKey, T> keyMapper
    ) {
        return Lists.newArrayList(this.secretKeyRings.getKeyRings())
                .stream()
                .flatMap(keyRing -> Lists.newArrayList(keyRing.getSecretKeys()).stream())
                .filter(keyFilter)
                .map(keyMapper);
    }

    @Override
    public Optional<PGPPrivateKey> getPrivateKey(Long keyId) {
        return Optional.ofNullable(this.privateKeys.get(keyId));
    }
}
