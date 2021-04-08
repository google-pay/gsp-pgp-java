// Copyright 2021 Google LLC
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

import com.google.common.collect.Sets;
import com.google.samples.pgp.PgpEncryptor.PgpDecryptionException;
import com.google.samples.pgp.PgpEncryptor.PgpEncryptionException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Set;

/**
 * A simple example on how to use the PgpEncryptor.
 */
public final class InteractiveExample {
    private static BufferedReader READER = new BufferedReader(new InputStreamReader(System.in));

    public static void main(String... args) throws IOException {
        String option;
        PgpKeyManager keyManager = new PgpKeyManager();
        PgpEncryptor encryptor = new PgpEncryptor(keyManager);

        do {
            System.out.print(
                    "### Options ###\n"
                            + "0. Toggle ASCII armor.\n"
                            + "1. Add encryption/signature verification key\n"
                            + "2. Add decryption/signing key\n"
                            + "3. Encrypt and sign plain text\n"
                            + "4. Decrypt cipher text and verify signature\n"
                            + "q! Exit.\n"
                            + "Selection: "
            );

            option = READER.readLine();
            System.out.println();

            try {
                switch (option) {
                    case "0":
                        encryptor.setAsciiArmour(!encryptor.isAsciiArmour());
                        System.out.println(
                                "ASCII armor " + (encryptor.isAsciiArmour() ? "enabled." : "disabled.")
                        );
                        break;
                    case "1":
                        addPublicKeys(keyManager);
                        break;
                    case "2":
                        addSecretKeys(keyManager);
                        break;
                    case "3":
                        encryptMessage(encryptor);
                        break;
                    case "4":
                        decryptMessage(encryptor);
                        break;
                }
            } catch (PgpException exception) {
                System.out.println(exception.getCause().getMessage());
            }

            System.out.println();
        } while (!"q!".equals(option));
    }

    private static void addPublicKeys(PgpKeyManager keyManager)
            throws IOException, KeyManagementException {
        System.out.print("Path to public key: ");
        String filePath = READER.readLine();

        try (InputStream input = openFile(filePath)) {
            keyManager.addPublicKeys(input);
            System.out.println("\n~ Public key chain:");
            keyManager.getPublicKeys()
                    .forEach(key -> {
                        Set<String> userIds = Sets.newHashSet(key.getUserIDs());
                        System.out.println(
                                String.format(
                                        "ID: %s, User: %s",
                                        Long.toHexString(key.getKeyID()),
                                        userIds
                                )
                        );
                    });
        } catch (IOException exception) {
            System.out.println(String.format("Problem with key file: %s", exception.getMessage()));
        }
    }

    private static InputStream openFile(String filePath) throws IOException {
        Path keyPath = Paths.get(filePath);

        if (Files.exists(keyPath) && Files.isRegularFile(keyPath)) {
            return Files.newInputStream(keyPath);
        } else {
            throw new IOException("Path does not point to a regular file.");
        }
    }

    private static void addSecretKeys(PgpKeyManager keyManager)
            throws IOException, KeyManagementException {
        System.out.print("Path to secret key: ");
        String filePath = READER.readLine();
        System.out.print("Secret key passphrase: ");
        char[] password = READER.readLine().toCharArray();

        try (InputStream input = openFile(filePath)) {
            keyManager.addSecretKeys(input, password);
            System.out.println("\n~ Secret keychain:");
            keyManager.getSecretKeys()
                    .forEach(key -> {
                        Set<String> userIds = Sets.newHashSet(key.getUserIDs());
                        System.out.println(
                                String.format(
                                        "ID: %s, User: %s",
                                        Long.toHexString(key.getKeyID()),
                                        userIds
                                )
                        );
                    });
        } catch (IOException exception) {
            System.out.println(String.format("Problem with key file: %s", exception.getMessage()));
        }
    }

    private static void encryptMessage(PgpEncryptor encrypter)
            throws IOException, PgpEncryptionException {
        System.out.print("Message to encrypt: ");
        String plainText = READER.readLine();

        System.out.print("Senders (separate with comma): ");
        String[] senders = splitUserInput();
        System.out.print("Receivers (separate with comma): ");
        String[] receivers = splitUserInput();

        String cipherText = encrypter.encrypt(plainText, senders, receivers);
        System.out.println(String.format("\nEncrypted message:\n%s\n", cipherText));
    }

    private static String[] splitUserInput() throws IOException {
        String userInput = READER.readLine();
        return userInput == null || "".equals(userInput.trim())
                ? new String[0]
                : userInput.split(",");
    }

    private static void decryptMessage(PgpEncryptor encrypter)
            throws IOException, PgpDecryptionException {
        System.out.print("Message to decrypt: ");
        String cipherText = READER.readLine();

        System.out.print("Senders (separate with comma): ");
        String[] senders = splitUserInput();
        System.out.print("Receivers (separate with comma): ");
        String[] receivers = splitUserInput();

        String plainText = encrypter.decrypt(cipherText, senders, receivers);
        System.out.println(String.format("\nDecrypted message:\n%s\n", plainText));
    }
}
