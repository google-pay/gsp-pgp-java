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

import java.io.Console;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
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
    private static PgpKeyManager KEY_MANAGER = PgpKeyManager.getInstance();

    public static void main(String... args) throws IOException, PgpException {
        new PgpTool().processRequest(args);
    }

    public void processRequest(String... args) throws IOException, PgpException  {
        Optional<CommandLine> parsedFlags = parseFlags(args);

        if (parsedFlags.isPresent()) {
            CommandLine commandLine = parsedFlags.get();
            addKeys(commandLine);
            PgpEncryptor encryptor = new PgpEncryptor(KEY_MANAGER);
            encryptor.setAsciiArmour(commandLine.hasOption("a"));
            String message = commandLine.getOptionValue("m");
            System.out.println(commandLine.hasOption("e")
                    ? encryptor.encrypt(message)
                    : encryptor.decrypt(message)
            );
        }
    }

    private Optional<CommandLine> parseFlags(String... args) {
        Options options = initOptions();
        CommandLineParser parser = new DefaultParser();
        HelpFormatter helpFormatter = new HelpFormatter();

        try {
            return Optional.of(parser.parse(options, args));
        } catch (ParseException exception) {
            helpFormatter.printHelp(this.getClass().getSimpleName(), options);
        }

        return Optional.empty();
    }

    private Options initOptions() {
        Options options = new Options();
        options.addRequiredOption("p", "public-key", true, "Public key path");
        options.addRequiredOption("s", "secret-key", true, "Secret key path");
        options.addRequiredOption("m", "message", true, "Message to process");

        options.addOption(
                "a", "ascii-armour", false, "ASCII armoured message"
        );
        options.addOption(
                "n", "no-passphrase", false, "No passphrase secret key"
        );

        OptionGroup mode = new OptionGroup();
        mode.addOption(new Option("e", "encrypt", false, "Encrypt plain text"));
        mode.addOption(new Option("d", "decrypt", false, "Decrypt cipher text"));
        options.addOptionGroup(mode);

        return options;
    }

    private void addKeys(CommandLine commandLine) throws IOException, KeyManagementException {
        Path publicKeyPath =  Paths.get(commandLine.getOptionValue("p"));
        Path secretKeyPath = Paths.get(commandLine.getOptionValue("s"));

        try (InputStream publicKeys = Files.newInputStream(publicKeyPath);
             InputStream secretKeys = Files.newInputStream(secretKeyPath)) {
            KEY_MANAGER.addPublicKeys(publicKeys);
            char[] passphrase = commandLine.hasOption("n")
                    ? new char[0]
                    : readSecretKeyPassphrase();
            KEY_MANAGER.addSecretKeys(secretKeys, passphrase);
            Arrays.fill(passphrase, '0');
        }
    }

    private char[] readSecretKeyPassphrase() {
        Console console = System.console();
        if (console == null) {
            throw new IllegalStateException("Error trying to access the console");
        }

        return console.readPassword("Secret key passphrase: ");
    }
}
