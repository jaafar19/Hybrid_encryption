package com.mkyong.hybrid.decrypt;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.spec.SecretKeySpec;

public class StartDecryption {
	
	public PrivateKey getPrivate(String filename, String algorithm) throws Exception {
		byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance(algorithm);
		return kf.generatePrivate(spec);
	}

    // Method to verify the signature of the data using a public key
    public boolean verifySignature(String data, String signaturePath, PublicKey publicKey, String algorithm) throws Exception {
        Signature sig = Signature.getInstance(algorithm);
		byte[] signature = Files.readAllBytes(new File(signaturePath).toPath());
		byte[] databyte = Files.readAllBytes(new File(data).toPath());

        sig.initVerify(publicKey);
        sig.update(databyte);
        return sig.verify(signature);
    }


    

	public PublicKey getPublic(String filename, String algorithm) throws Exception {
		byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance(algorithm);
		return kf.generatePublic(spec);
	}
	
	public SecretKeySpec getSecretKey(String filename, String algorithm) throws IOException{
		byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
		return new SecretKeySpec(keyBytes, algorithm);
	}

	public static void main(String[] args) throws IOException, GeneralSecurityException, Exception{
		StartDecryption startEnc = new StartDecryption();

		// Verify the signature
        boolean isSignatureValid = startEnc.verifySignature("EncryptedFiles/encryptedSecretKey", "EncryptedFiles/signature",
                startEnc.getPublic("KeyPair/publicKey_Alice", "RSA"), "SHA256withRSA");
	
        if (isSignatureValid) {
            System.out.println("Signature is valid.");
			
        } else {
            System.out.println("Signature is NOT valid.");
        }
	
        // ... (perform other operations if needed)
    
	   // ... (existing code)

		       if (isSignatureValid) {
		File encryptedKeyReceived = new File("EncryptedFiles/encryptedSecretKey");
		File decreptedKeyFile = new File("DecryptedFiles/SecretKey");
		new DecryptKey(startEnc.getPrivate("KeyPair/privateKey_Bob", "RSA"), encryptedKeyReceived, decreptedKeyFile, "RSA");
		
		File encryptedFileReceived = new File("EncryptedFiles/encryptedFile");
		File decryptedFile = new File("DecryptedFiles/decryptedFile");
		new DecryptData(encryptedFileReceived, decryptedFile, startEnc.getSecretKey("DecryptedFiles/SecretKey", "AES"), "AES");
									}
	}
}
