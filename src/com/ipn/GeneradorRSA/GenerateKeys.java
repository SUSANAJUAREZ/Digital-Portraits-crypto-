package com.ipn.GeneradorRSA;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;

public class GenerateKeys {

    private KeyPairGenerator keyGen;
    private KeyPair pair;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public GenerateKeys(int keylength) throws NoSuchAlgorithmException, NoSuchProviderException {

        this.keyGen = KeyPairGenerator.getInstance("RSA");
        this.keyGen.initialize(keylength);
    }

    public void createKeys() {
        this.pair = this.keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();

    }

    public PrivateKey getPrivateKey() {
        return this.privateKey;
    }

    public PublicKey getPublicKey() {
        return this.publicKey;
    }

    public void writeToFile(String path, byte[] key) throws IOException {

        File f = new File(path);
        f.getParentFile().mkdirs();

        FileOutputStream fos = new FileOutputStream(f);
        fos.write(key);
        fos.flush();
        fos.close();

    }

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
        GenerateKeys myKeys = new GenerateKeys(1024);
        myKeys.createKeys();
        System.out.println("La llave publica es: " + Arrays.toString(myKeys.publicKey.getEncoded()));
        System.out.println("La llave privada es: " + Arrays.toString(myKeys.privateKey.getEncoded()));
        myKeys.writeToFile("Llaves/publicKey.txt", Base64.getEncoder().encode(myKeys.getPublicKey().getEncoded()));
        myKeys.writeToFile("Llaves/privateKey.txt", Base64.getEncoder().encode(myKeys.getPrivateKey().getEncoded()));
    }
}