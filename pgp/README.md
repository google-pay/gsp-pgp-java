# PGP Encryption Example

**DISCLAIMER**: This is not an officially supported Google product.

This directory contains examples on how to do PGP multi-key encryption with
base64 encoding, as stated in the
[best practices](https://developers.google.com/standard-payments/reference/best-practices)
for implementing the Google Standard Payments API.

Please note that this sample uses the Bouncy Castle security provider and serves
only as an example.

## How to use it:

This sample can be built using maven for your convenience:

```shell
  $ cd $REPOSITORY_PATH/samples/pgp
  $ mvn package
```

Once it is compiled, you can run the interactive example:

```shell
  $ java -cp "target/*" com.google.samples.pgp.InteractiveExample
```

The interactive example provides a quick way to explore the functionality that
this example exposes. It will require you to provide public and secret keys to
experiment with but in case you do not have any you can use the files included
in the `resources` folder.

Additionally, you can use the PgpTool class to quickly encrypt or decrypt a
message using a PGP key pair:

```shell
  $ java -cp "target/*" com.google.samples.pgp.PgpTool
```

The class supports the following flags:

```shell
 -a,--ascii-armour       ASCII armoured message
 -c,--encoding <arg>     Binary-to-text encoding scheme
 -d,--decrypt            Decrypt cipher text
 -e,--encrypt            Encrypt plain text
 -f,--file <arg>         Path of the file to process
 -k,--secret-key <arg>   Secret key path
 -m,--message <arg>      Message to process
 -n,--no-passphrase      No passphrase secret key
 -o,--output <arg>       Destination file path
 -p,--public-key <arg>   Public key path
 -r,--recipient <arg>    ID of the recipient
 -s,--sender <arg>       ID of the sender
```

## How the example works

In a nutshell, there are two main components in the example:

1.  **PgpKeyManager** Acts as a key store and provider of public, secret, and
    private PGP keys. Implemented as a singleton.
2.  **PgpEncryptor** The encryption/decryption engine. Supports ASCII armoured
    messages. Requires a PgpKeyManager.

You can initialise the PgpKeyManager and add public and secret key chains as
easily as:

```java
  static final Path PUBLIC_KEYS_PATH = Paths.get("src/main/resources/public.asc");
  static final Path SECRET_KEYS_PATH = Paths.get("src/main/resources/private.asc");

  ...

  KeyManager keyManager = PgpKeyManager.getInstance();

  try (InputStream publicKeys = Files.newInputStream(PUBLIC_KEYS_PATH);
       InputStream secretKeys = Files.newInputStream(SECRET_KEYS_PATH)) {
      keyManager.addPublicKeys(publicKeys);
      keyManager.addSecretKeys(secretKeys, ALICE_PASSPHRASE, BOB_PASSPHRASE);
  }
```

Then you can inject the PgpKeyManager to a PgpEncryptor instance and use it as
it is shown below:

```java
  PgpEncryptor encryptor = new PgpEncryptor(PgpKeyManager.getInstance());
  String cipherText = encryptor.encrypt(plainText);
  String plainText = encryptor.decrypt(cipherText);
```

### File Encryption

You can also use the example to handle file encryption and decryption. A quick
encryption example below:

```java
  Path inputPath = Paths.get(filePath);
  Path outputPath = Paths.get(outputFilePath);

  try(InputStream inputStream = Files.newInputStream(inputPath, ...);
      OutputStream outputStream = Files.newOutputStream(outputPath, ...)) {
    encryptor.encrypt(inputStream, outputStream, senders, recipients);
  } catch (PgpException | KeySearchException exception) {
    Files.deleteIfExists(outputPath);
    throw exception;
  }
```

### Using it in a Web App

Since the intention of recurring to this sample might be to implement the GSP
API and the use you might want to use this is in a Web App. You can plug in the
KeyManager in your security configuration module so that your App loads the PGP
keys only once at boot time. Then, you can have the HTTP/REST handlers to have a
[`ThreadLocal<PgpEncryptor>`](https://docs.oracle.com/javase/8/docs/api/java/lang/ThreadLocal.html)
that borrows the required keys from the security module and takes care of the
encryption/decryption per HTTP request thread.

A simple example on how to achieve this is in
`src/test/java/com/google/samples/pgp/PgpEncryptorTest.java`:

```java
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
```

## Some cheat codes

To generate a PGP key:

```shell
  $ gpg --full-generate-key
```

To export a secret key:

```shell
  $ gpg --export-secret-key -a "alice@example.com"
```

To export a public key:

```shell
  $ gpg --export -a "alice@example.com"
```

To import a key:

```shell
  $ gpg --import $KEY_PATH
```

To encrypt and ASCII armour a message to a recipient from a sender:

```shell
  $ gpg -ea -u "alice@example.com" -r "bob@example.com" <<HERE
  Some message to encrypt.
  HERE
```

## Additional Resources

You might want to take a look at the
[OpenPGP Message Format RFC](https://tools.ietf.org/html/rfc4880).
