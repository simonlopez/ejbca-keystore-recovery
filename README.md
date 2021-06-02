# EJBCA keystore password recovery

A simple tool to recover keystore password from pin in SoftCryptoToken stored in [EJBCA](https://www.ejbca.org/) database.

In case you need to extract private key of a CA but you forgotten to select "Allow export of private keys" option when creating a new CA, you may need this tool.

This tool have been tested with EJBCA 6.2.0 but shall work with other versions.

## Usage

### Display help

You can diplay help using --help parameter:
```
$ java -jar --help
```
### Decode SoftCryptoToken

To decode from SoftToken retreived in EJBCA database (```tokenProps``` field of ```CryptoTokenData``` table), you can use --token parameter with the BASE64 encoded Token directly:
```
$ java -jar keystore-password-recovery-1.0.jar --token="BASE64TOKEN"
```

### Decode pin

If you already retreived pin, you can decode it using --pin parameter:
```
$ java -jar keystore-password-recovery-1.0.jar --pin="pin"
```

### Defining password encryption key

By default, EJBCA use a predefined password encryption key. It is higly recommended to change it. If you did it, then you have to use --password-encryption-key parameter in addition to pin or token parameter:

```
$ java -jar keystore-password-recovery-1.0.jar --password-encryption-key="YOUR_SECRET_KEY" --token="BASE64TOKEN"
$ java -jar keystore-password-recovery-1.0.jar --password-encryption-key="YOUR_SECRET_KEY" --pin="pin"
```