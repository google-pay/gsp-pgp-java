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

import java.io.Console;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.Optional;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionGroup;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

/**
 * A CLI util to encrypt and decrypt messages with a particular key pair.
 */
public final class PgpTool {
    private enum Mode {
        ENCRYPT,
        DECRYPT,
    };

    private static final Options OPTIONS = PgpTool.createOptions();
    private static final PgpKeyManager KEY_MANAGER = PgpKeyManager.getInstance();

    private final PgpEncryptor encryptor;
    private CommandLine commandLine;

    private PgpTool() {
        this.encryptor = new PgpEncryptor(KEY_MANAGER);
    }

    public void processRequest(String... args) throws IOException, PgpException  {
        Optional<CommandLine> parsedFlags = parseFlags(args);

        if (parsedFlags.isPresent()) {
            this.commandLine = parsedFlags.get();
            addKeys();
            this.encryptor.setAsciiArmour(this.commandLine.hasOption('a'));

            if (this.commandLine.hasOption('c')) {
                BinaryToTextEncoding encoding = BinaryToTextEncoding.valueOf(this.commandLine.getOptionValue('c'));
                encryptor.setBinaryToTextEncoding(encoding);
            }

            String[] senders = commandLine.hasOption('s')
                    ? new String[]{commandLine.getOptionValue('s')}
                    : new String[]{};
            String[] recipients = commandLine.hasOption('r')
                    ? new String[]{commandLine.getOptionValue('r')}
                    : new String[]{};

            Mode mode = commandLine.hasOption("e") ? Mode.ENCRYPT : Mode.DECRYPT;

            if (this.commandLine.hasOption('m')) {
                processText(senders, recipients, mode);
            } else {
                processFile(senders, recipients, mode);
            }
        }
    }

    private Optional<CommandLine> parseFlags(String... args) {
        CommandLineParser parser = new DefaultParser();
        HelpFormatter helpFormatter = new HelpFormatter();

        try {
            return Optional.of(parser.parse(OPTIONS, args));
        } catch (ParseException exception) {
            helpFormatter.printHelp(this.getClass().getSimpleName(), OPTIONS);
        }

        return Optional.empty();
    }

    private void addKeys() throws IOException, KeyManagementException {
        Path publicKeyPath =  Paths.get(this.commandLine.getOptionValue("p"));
        Path secretKeyPath = Paths.get(this.commandLine.getOptionValue("k"));

        try (InputStream publicKeys = Files.newInputStream(publicKeyPath);
             InputStream secretKeys = Files.newInputStream(secretKeyPath)) {
            KEY_MANAGER.addPublicKeys(publicKeys);
            char[] passphrase = this.commandLine.hasOption("n")
                    ? new char[0]
                    : readSecretKeyPassphrase();
            KEY_MANAGER.addSecretKeys(secretKeys, passphrase);
            Arrays.fill(passphrase, '0');
        }
    }

    private void processText(String[] senders, String[] recipients, Mode mode)  throws PgpException {
        String message = commandLine.getOptionValue("m");

        System.out.println(Mode.ENCRYPT.equals(mode)
                ? encryptor.encrypt(message, senders, recipients)
                : encryptor.decrypt(message, senders, recipients)
        );
    }

    private void processFile(String[] senders, String[] recipients, Mode mode)  throws IOException, PgpException {
        String filePath = this.commandLine.getOptionValue("f");
        String outputFilePath = filePath;

        if (Mode.ENCRYPT.equals(mode)) {
            outputFilePath += ".gpg";
        } else {
            if (outputFilePath.endsWith(".gpg")) {
                outputFilePath = outputFilePath.substring(0, outputFilePath.lastIndexOf('.'));
            }
        }

        if (this.commandLine.hasOption("o")) {
            outputFilePath = this.commandLine.getOptionValue("o");
        }

        Path inputPath = Paths.get(filePath);
        Path outputPath = Paths.get(outputFilePath);

        try (
                InputStream inputStream = Files.newInputStream(inputPath, StandardOpenOption.READ);
                OutputStream outputStream = Files.newOutputStream(outputPath, StandardOpenOption.CREATE_NEW)
        ) {
            if (Mode.ENCRYPT.equals(mode)) {
                encryptor.encrypt(inputStream, outputStream, senders, recipients);
            } else {
                encryptor.decrypt(inputStream, outputStream, senders, recipients);
            }
        } catch (PgpException | KeySearchException exception) {
            System.out.println("Cleaning output file: " + outputPath);
            Files.deleteIfExists(outputPath);
            throw exception;
        }
    }

    private static Options createOptions() {
        Options options = new Options();
        Option option = new Option("p", "public-key", true, "Public key path");
        option.setRequired(true);
        options.addOption(option);
        option = new Option("k", "secret-key", true, "Secret key path");
        option.setRequired(true);
        options.addOption(option);

        options.addOption("a", "ascii-armour", false, "ASCII armoured message");
        options.addOption("c", "encoding", true, "Binary-to-text encoding scheme");
        options.addOption("n", "no-passphrase", false, "No passphrase secret key");
        options.addOption("o", "output", true, "Destination file path");
        options.addOption("s", "sender", true, "ID of the sender");
        options.addOption("r", "recipient", true, "ID of the recipient");

        OptionGroup input = new OptionGroup();
        input.addOption(new Option("m", "message", true, "Message to process"));
        input.addOption(new Option("f", "file", true, "Path of the file to process"));
        input.setRequired(true);
        options.addOptionGroup(input);

        OptionGroup mode = new OptionGroup();
        mode.addOption(new Option("e", "encrypt", false, "Encrypt plain text"));
        mode.addOption(new Option("d", "decrypt", false, "Decrypt cipher text"));
        mode.setRequired(true);
        options.addOptionGroup(mode);

        return options;
    }

    private static char[] readSecretKeyPassphrase() {
        Console console = System.console();
        if (console == null) {
            throw new IllegalStateException("Error trying to access the console");
        }

        return console.readPassword("Secret key passphrase: ");
    }

    public static void main(String... args) {
        try {
            new PgpTool().processRequest(args);
        } catch (RuntimeException | IOException | PgpException exception) {
            System.out.println(exception);
        }
    }
}
