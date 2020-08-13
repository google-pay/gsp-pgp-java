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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * PgpEncryptor test cases.
 */
class PgpEncryptorTest {
    private static final Path PUBLIC_KEYS_PATH = Paths.get("src/main/resources/public.asc");
    private static final Path SECRET_KEYS_PATH = Paths.get("src/main/resources/private.asc");
    private static final char[] ALICE_PASSPHRASE = "alice".toCharArray();
    private static final String ALICE_ID = "Alice <alice@example.com>";
    private static final char[] BOB_PASSPHRASE = "bob".toCharArray();
    private static final String BOB_ID = "Bob <bob@example.com>";
    private static final String CHUCK_ID = "Chuck <chuck@example.com>";

    @BeforeAll
    static void addKeys() throws IOException, KeyManagementException {
        KeyManager keyManager = PgpKeyManager.getInstance();

        try (InputStream publicKeys = Files.newInputStream(PUBLIC_KEYS_PATH);
             InputStream secretKeys = Files.newInputStream(SECRET_KEYS_PATH)) {
            keyManager.addPublicKeys(publicKeys);
            keyManager.addSecretKeys(secretKeys, ALICE_PASSPHRASE, BOB_PASSPHRASE);
        }
    }

    @Test
    void multiThreadEncryption() {
        ThreadLocal<PgpEncryptor> encryptor =
                ThreadLocal.withInitial(() -> new PgpEncryptor(PgpKeyManager.getInstance()));

        IntStream.range(1, 10)
                .parallel()
                .forEach(number -> {
                    PgpEncryptor threadEncryptor = encryptor.get();
                    String plainText = RandomStringUtils.random(10, true, true);
                    String result = decryptBack(threadEncryptor, plainText);
                    assertEquals(plainText, result);
                });
    }

    static String decryptBack(PgpEncryptor encryptor, String plainText) {
        try {
            return encryptor.decrypt(encryptor.encrypt(plainText));
        } catch (PgpException exception) {
            throw new RuntimeException(exception);
        }
    }

    private static Stream<Arguments> validMultiKeyEncryptionParameters() {
        return Stream.of(
                Arguments.of(new String[]{}, new String[]{}),
                Arguments.of(new String[]{ALICE_ID}, new String[]{}),
                Arguments.of(new String[]{BOB_ID}, new String[]{}),
                Arguments.of(new String[]{ALICE_ID}, new String[]{BOB_ID}),
                Arguments.of(new String[]{BOB_ID}, new String[]{ALICE_ID}),
                Arguments.of(new String[]{}, new String[]{ALICE_ID}),
                Arguments.of(new String[]{}, new String[]{BOB_ID}),
                Arguments.of(new String[]{ALICE_ID, BOB_ID}, new String[]{}),
                Arguments.of(new String[]{BOB_ID, ALICE_ID}, new String[]{}),
                Arguments.of(new String[]{ALICE_ID, BOB_ID}, new String[]{ALICE_ID}),
                Arguments.of(new String[]{ALICE_ID, BOB_ID}, new String[]{BOB_ID}),
                Arguments.of(new String[]{BOB_ID, ALICE_ID}, new String[]{ALICE_ID}),
                Arguments.of(new String[]{BOB_ID, ALICE_ID}, new String[]{BOB_ID}),
                Arguments.of(new String[]{}, new String[]{ALICE_ID, BOB_ID}),
                Arguments.of(new String[]{}, new String[]{BOB_ID, ALICE_ID})
        );
    }

    @ParameterizedTest
    @MethodSource("validMultiKeyEncryptionParameters")
    void multiKeyEncryption(String[] senders, String[] recipients) throws PgpException {
        PgpEncryptor encryptor = new PgpEncryptor(PgpKeyManager.getInstance());
        String plainText = RandomStringUtils.random(10, true, true);
        String cipherText = encryptor.encrypt(plainText, senders, recipients);
        String result = encryptor.decrypt(cipherText, senders, recipients);
        assertEquals(plainText, result);
    }

    private static Stream<Arguments> invalidMultiKeyEncryptionParameters() {
        return Stream.of(
                Arguments.of(new String[]{}, new String[]{CHUCK_ID}),
                Arguments.of(new String[]{CHUCK_ID}, new String[]{}),
                Arguments.of(new String[]{CHUCK_ID}, new String[]{ALICE_ID}),
                Arguments.of(new String[]{CHUCK_ID}, new String[]{BOB_ID}),
                Arguments.of(new String[]{ALICE_ID}, new String[]{CHUCK_ID}),
                Arguments.of(new String[]{BOB_ID}, new String[]{CHUCK_ID}),
                Arguments.of(new String[]{ALICE_ID, BOB_ID}, new String[]{CHUCK_ID}),
                Arguments.of(new String[]{BOB_ID, ALICE_ID}, new String[]{CHUCK_ID}),
                Arguments.of(new String[]{CHUCK_ID}, new String[]{ALICE_ID, BOB_ID})
        );
    }

    @ParameterizedTest
    @MethodSource("invalidMultiKeyEncryptionParameters")
    void failingMultiKeyEncryption(String[] senders, String[] recipients) {
        PgpEncryptor encryptor = new PgpEncryptor(PgpKeyManager.getInstance());
        String plainText = RandomStringUtils.random(10, true, true);

        assertThrows(PgpException.class, () -> {
            String cipherText = encryptor.encrypt(plainText, senders, recipients);
            encryptor.decrypt(cipherText, senders, recipients);
        });
    }
}
