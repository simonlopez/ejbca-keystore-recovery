/*
 * Copyright 2021 Simon Lopez <simon.lopez@slopez.fr>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package fr.slopez.ejbca;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import java.security.Security;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.util.encoders.Base64;

/**
 *
 * @author Simon Lopez <simon.lopez@worldline.com>
 */
public class KeystorePasswordRecovery {

    private static final String ALGORITHM = "PBEWithSHA256And192BitAES-CBC-BC";

    private static final byte[] DEFAULT_SALT = "1958473059684739584hfurmaqiekcmq".getBytes(StandardCharsets.UTF_8);

    private static final int DEFAULT_COUNT = 100;

    private static final String DEFAULT_PASSWORD_ENCRYPTION_KEY = "qhrnf.f8743;12%#75";
    
    private static final Set<String> PARAMETERS = new HashSet<>(Arrays.asList(new String[]{"pin","password-encryption-key","token"}));

    private static Map<String, String> parseParameters(final String[] args) {

        final Map<String, String> parameters = new HashMap<>();

        for (final String arg : args) {
            if (!arg.startsWith("--")) {
                System.err.println("Bad parameter: " + arg);
                displayHelp();
            }
            if(arg.equals("--help")) {
                displayHelp();
                
            }
            final String[] tab = arg.substring(2).split("=",2);
            if(tab.length!=2 || !PARAMETERS.contains(tab[0])) {
                System.err.println("Bad parameter: " + arg);
                displayHelp();
            }
            parameters.put(tab[0], tab[1]);
        }

        return parameters;
    }
    
    private static void displayHelp() {
        System.out.println("Parameters: ");
        System.out.println("\t --pin=PINCODE specify pin code to decrypt");
        System.out.println("\t --token=TOKEN Base64 encoded SoftCryptoToken");
        System.out.println("\t --password-encryption-key=KEY password encryption key if different from default one (default: "+DEFAULT_PASSWORD_ENCRYPTION_KEY+")");
        System.out.println("\t --help display this help");
        System.exit(0);
    }

    public static void main(String[] args) {
        // install BouncyCastleProvider if needed
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null && Security.addProvider(new BouncyCastleProvider()) < 0) {
            System.err.println("Failed to add BC");
            System.exit(1);
        }
        
        final Map<String, String> parameters = parseParameters(args);
        
        String pin;
        String token = parameters.get("token");

        if(token == null) {
            pin = parameters.get("pin");
        } else {
            token = new String(Base64.decode(token));
            int start = token.indexOf("pin=")+4;
            if(start<4) {
                System.err.println("Invalid SoftCryptoToken");
                System.exit(1);
            }
            int end = token.indexOf("\n", start);
            if(end == -1) {
                pin = token.substring(start);
            } else {
                pin = token.substring(start, end);
            }
            start = token.indexOf("tokenName=")+10;
            if(start>=10) {
                end = token.indexOf("\n", start);
                String tokenName;
                if(end == -1) {
                    tokenName = token.substring(start);
                } else {
                    tokenName = token.substring(start, end);
                }
                System.out.println("Token Name: "+ tokenName);
            } else {
                System.out.println("Token Name: not found");
            }
        }
        if(pin == null) {
            displayHelp();
            return;
        }
        
        final byte[] salt;
        int count;
        
        if (pin.contains(":")) {
            // this is a newer version that has encryption version and parameters in it
            String[] strs = pin.split(":");
            if (strs.length != 4) {
                System.err.println("Invalid input pin");
                System.exit(3);
            }
            salt = Hex.decode(strs[1].getBytes(StandardCharsets.UTF_8));
            count = Integer.valueOf(strs[2]);
            pin = strs[3];
        } else {
            salt = DEFAULT_SALT;
            count = DEFAULT_COUNT;
        }
        
        final char[] p;
        String passwordEncryptionKey = parameters.get("password-encryption-key");
        if(passwordEncryptionKey != null && !passwordEncryptionKey.isEmpty()) {
            p = passwordEncryptionKey.toCharArray();
        } else {
            p = DEFAULT_PASSWORD_ENCRYPTION_KEY.toCharArray();
        }
        try {
            final Cipher c = Cipher.getInstance(ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
            final PBEKeySpec keySpec = new PBEKeySpec(p, salt, count);
            final SecretKeyFactory fact = SecretKeyFactory.getInstance(ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
            c.init(Cipher.DECRYPT_MODE, fact.generateSecret(keySpec));
            final byte[] dec = c.doFinal(Hex.decode(pin.getBytes(StandardCharsets.UTF_8)));
            System.out.println("Decoded keystore password: "+new String(dec));
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
            System.err.println("Failed with error: "+e.getMessage());
        }

    }
}
