/**
 * Created by Constantin Mihail Andrei on 25/05/2019.
 * Proiect Securitatea documentelor electronice
 *
 *
 */

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Scanner;


public class BouncyCastleRas {

    public static String getHexString(byte[] b) throws Exception {
        String result = "";
        for (int i = 0; i < b.length; i++) {
            result +=
                    Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
        }
        return result;
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public static AsymmetricCipherKeyPair generateKeys() throws NoSuchAlgorithmException {
        RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
        generator.init(new RSAKeyGenerationParameters
                (
                        new BigInteger("10001", 16),//exponentul public
                        SecureRandom.getInstance("SHA1PRNG"),//generator de numere pseudo aleatoare
                        4096,//taria
                        80//certitudine
                ));

        return generator.generateKeyPair();
    }

    public static String encrypt(byte[] data, AsymmetricKeyParameter publicKey) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        RSAEngine engine = new RSAEngine();
        engine.init(true, publicKey); //true if encrypt

        byte[] hexEncodedCipher = engine.processBlock(data, 0, data.length);

        return getHexString(hexEncodedCipher);
    }

    public static String decrypt(String encrypted, AsymmetricKeyParameter privateKey) throws InvalidCipherTextException {

        AsymmetricBlockCipher engine = new RSAEngine();
        engine.init(false, privateKey); //false for decryption

        byte[] encryptedBytes = hexStringToByteArray(encrypted);
        byte[] hexEncodedCipher = engine.processBlock(encryptedBytes, 0, encryptedBytes.length);

        return new String(hexEncodedCipher);
    }

    public static void main(String[] args) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        Scanner scan = new Scanner(System.in);
        System.out.println("Mesajul ce trebuie criptat este: ");
        String message = scan.nextLine();

        System.out.println("Se genereaza perechea de cheile...");
        AsymmetricCipherKeyPair keyPair = generateKeys();

        System.out.println("Se cripteaza mesajul...");
        String encryptedMessage = encrypt(message.getBytes("UTF-8"), keyPair.getPublic());
        System.out.println("Mesajul a fost criptat cu succes!");
        System.out.println("cheia este:" + encryptedMessage);

        System.out.println("Se decripteaza mesajul... ");
        String decryptedMessage = decrypt(encryptedMessage, keyPair.getPrivate());
        System.out.println("Mesajul a fost: " + message + " si textul decriptat este: " + decryptedMessage);

    }

}

