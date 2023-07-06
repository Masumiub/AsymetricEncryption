package encryptionanddecryption;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Scanner;
 
import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;
/**
 *
 * @author md.masum
 */
public class EncryptionAndDecryption {

    private static final String RSA = "RSA";
    private static Scanner sc;
    
    public static KeyPair generateRSAKkeyPair()throws Exception
    {
        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
 
        keyPairGenerator.initialize(2048, secureRandom);
        
        return keyPairGenerator.generateKeyPair();
    }
        
    public static byte[] do_RSAEncryption( String plainText, PrivateKey privateKey) throws Exception
    {
        Cipher cipher = Cipher.getInstance(RSA);
 
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
 
        return cipher.doFinal(plainText.getBytes());
    }
    
    
    public static String do_RSADecryption(byte[] cipherText, PublicKey publicKey)throws Exception
    {
        Cipher cipher = Cipher.getInstance(RSA);
 
        cipher.init(Cipher.DECRYPT_MODE,publicKey);
        
        byte[] result = cipher.doFinal(cipherText);
 
        return new String(result);
    }
    
    public static void main(String[] args) throws Exception{
        // TODO code application logic here
        KeyPair keypair = generateRSAKkeyPair();
 
        //String plainText = "This is the Sample PlainText. Lets Encrypt This!";
        Scanner scanner = new Scanner(System.in);
        
        System.out.print("Enter a string for Assymetric encryption: ");
        
        String plainText = scanner.nextLine();
        
        scanner.close();
 
        byte[] cipherText = do_RSAEncryption(plainText, keypair.getPrivate());
 
        System.out.println( "The Public Key is: " + DatatypeConverter.printHexBinary(
                  keypair.getPublic().getEncoded()));
 
        System.out.println("The Private Key is: " + DatatypeConverter.printHexBinary(
                  keypair.getPrivate().getEncoded()));
 
        System.out.print("The Encrypted Text is: ");
 
        System.out.println(DatatypeConverter.printHexBinary(cipherText));
 
        String decryptedText= do_RSADecryption(cipherText,keypair.getPublic());
 
        System.out.println("The decrypted text is: "+ decryptedText);
        
    }
    
}
