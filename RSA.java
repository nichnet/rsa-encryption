import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;

public class RSA {

    public static String[] generateKeys() {
    	try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            
            KeyPair keys = keyGen.generateKeyPair();
            
            return new String[] {
        		Base64.getEncoder().encodeToString(keys.getPublic().getEncoded()),
        		Base64.getEncoder().encodeToString(keys.getPrivate().getEncoded()),
            };    		
    	} catch(NoSuchAlgorithmException e) {
    		return null;
    	}
    }
  
    public static String encrypt(String publicKeyStr, String value) {
    	try {
        	byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyStr.getBytes());
        	byte[] valueBytes = value.getBytes(StandardCharsets.UTF_8);
        	
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(keySpec);

            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            return Base64.getEncoder().encodeToString(cipher.doFinal(valueBytes));    		
    	} catch(Exception e) {
    		return null;
    	}
    }
    
    
    public static String decrypt(String privateKeyStr, String value) {
    	try {
        	byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyStr.getBytes());
        	byte[] valueBytes = Base64.getDecoder().decode(value.getBytes());
            
    		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            return new String(cipher.doFinal(valueBytes), StandardCharsets.UTF_8);    		
    	} catch(Exception e) {
    		return null;
    	}
    }
    
    public static void main(String[] args) {
        String originalMessage = "This `s RSA Encryption Using PUBL1C/PRIVAT3 Key$";
        System.out.println("Original Message: " + originalMessage);
        
        String[] keys = generateKeys();
        
        if(keys == null) {
        	System.out.println("Unable to generate keys.");
        	return;
        }
        
        String publicKey = keys[0];
        String privateKey = keys[1];
        System.out.println("Public Key: " + publicKey);
        System.out.println("Private Key: " + privateKey);
        
        String encryptedData = encrypt(publicKey, originalMessage);
        System.out.println("Encrypted Data: " + encryptedData);

        String decryptedData = decrypt(privateKey, encryptedData);
        System.out.println("Decrypted Data: " + decryptedData);
    }
}
