package com.mkyong.hybrid.encrypt;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.spec.SecretKeySpec;




public class StartEncryption {
	
    public byte[] signData(byte[] data, PrivateKey privateKey, String algorithm) throws Exception {
        Signature signature = Signature.getInstance(algorithm);
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

	public PrivateKey getPrivate(String filename, String algorithm) throws Exception {
		byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance(algorithm);
		return kf.generatePrivate(spec);
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
		StartEncryption startEnc = new StartEncryption();
		
		File originalKeyFile = new File("OneKey/secretKey");
		File encryptedKeyFile = new File("EncryptedFiles/encryptedSecretKey");
		new EncryptKey(startEnc.getPublic("KeyPair/publicKey_Bob", "RSA"), originalKeyFile, encryptedKeyFile, "RSA");

		PrivateKey privateKey = startEnc.getPrivate("KeyPair/privateKey_Alice", "RSA");

        // Sign the original key file
        byte[] signature = startEnc.signData(Files.readAllBytes(new File("EncryptedFiles/encryptedSecretKey").toPath()), privateKey, "SHA256withRSA");

        // Save the signature to a file
        Files.write(new File("EncryptedFiles/signature").toPath(), signature, StandardOpenOption.CREATE);

		
		File originalFile = new File("confidential.txt");
		File encryptedFile = new File("EncryptedFiles/encryptedFile");
		new EncryptData(originalFile, encryptedFile, startEnc.getSecretKey("OneKey/secretKey", "AES"), "AES");
	}
}
