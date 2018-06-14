package com.ipn.CifradorRSA;

import static com.ipn.CifradorImagenAES.ImageEncDec.getFile;
import static com.ipn.CifradorImagenAES.ImageEncDec.saveFile;
import com.ipn.util.Ventanas;
import java.io.File;
import java.io.IOException;
import static java.lang.System.exit;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JOptionPane;
//import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

/**
 *
 * @author yeyof
 */
public class CifradorRSA {

    /*
    getPublic() es un método que sirve para obtener una variable PublicKey.
    El método nos regreserá la llave publica del archivo que le ingresemos.
    Recibe como parametro un String que es el nombre del archivo donde está nuestra llave publica.
    */
    public static PublicKey getPublic(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.getDecoder().decode(keyBytes));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    /*
    getPrivate es un método que sirve para obtener una variable PrivateKey.
    El método nos regresará la llave privada del archivo que le ingresemos.
    Recibe como parametro un String que es el nombre del archivo donde está nuestra llave privada.
    */
    public static PrivateKey getPrivate(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(keyBytes));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    /*
    CifrarRSA() se encarga de cifrar mediante RSA el contenido de la llaveAES con modo CBC.
    Recibe como parametros un PublicKey (llave publica con la que se cifrará) y un
    arreglo de bytes (contenido del archivo llaveAES en forma de bytes).
    El método retornará la llaveAES cifrada pero en forma de bytes (byte[]) 
    */
    public static byte[] CifrarRSA(PublicKey llavepublica, byte[] llaveAES) {
        Cipher cipher;
        byte[] encrypted = null;

        try {
            cipher = Cipher.getInstance("RSA/NONE/PKCS1Padding");
            cipher.init(Cipher.PUBLIC_KEY, llavepublica);
            encrypted = cipher.doFinal(llaveAES);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return encrypted;
    }
    
    
    /*
    DescifrarRSA se encarga de descifrar mediante RSA el contenido de la llaveAESCifrada con modo CBC.
    Recibe como parametros un PrivateKey (llave privada con la que se descifrará) y un
    arreglo de bytes (contenido del archivo llaveAESCifrada en forma de bytes).
    El método retornará la llaveAES original pero en forma de bytes (byte[]) 
    */
    public static byte[] DescifrarRSA(PrivateKey llaveprivada, byte[] llaveAES) {
        Cipher cipher;
        byte[] decrypted = null;
        try {
            cipher = Cipher.getInstance("RSA/NONE/PKCS1Padding");
            cipher.init(Cipher.PRIVATE_KEY, llaveprivada);
            decrypted = cipher.doFinal(llaveAES);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return decrypted;
    }
    
    

//    public static void main(String args[])
//            throws NoSuchAlgorithmException, InstantiationException, IllegalAccessException, IOException, NoSuchProviderException, Exception {
//        Security.addProvider(new BouncyCastleFipsProvider());
//        File llave = null;
//        PublicKey pubkey;
//        PrivateKey privkey;
//        String llavepublica, llaveprivada, archllave, kname;
//        byte[] llaveAES, encrypted, decrypted;
//        int opc;
//        do {
//            System.out.println("--------Cifrador de imagen--------"
//                    + "\n 1.-Cifrar llave\n"
//                    + "2.-Descifrar llave\n"
//                    + "3.-Salir");
//            opc = Ventanas.entradaI("Seleccione una opcion");
//            switch (opc) {
//                case 1:
//                    //Obtenemos el contenido (en bytes) del archivo llaveAES
//                    kname = Ventanas.entradaS("Ingrese el nombre del archivo de la llave AES para cifrar");
//                    llaveAES = Base64.getDecoder().decode(getFile("LlavesAES/", kname + ".txt"));
//                    System.out.println(llaveAES);
//
//                    //Obtenemos en forma de variable PublicKey la llave pública con la que cifraremos la llave AES
//                    llavepublica = JOptionPane.showInputDialog("Ingrese nombre del archivo de llave publica");
//                    pubkey = getPublic("Llaves/" + llavepublica + ".txt");
//                    System.out.println(pubkey);
//
//                    //Parte que se encarga de cifrar el contenido de llaveAES con la llave publica
//                    encrypted = CifrarRSA(pubkey, llaveAES);
//                    System.out.println(encrypted);
//
//                    archllave = JOptionPane.showInputDialog("Ingrese nombre para guardar el archivo cifrado");
//                    saveFile(Base64.getEncoder().encode(encrypted), "CifradoRSA/", archllave);
//                    
//                    /*
//                    La linea de abajo sirve para crear un File a partir del arreglo encrypted.
//                    Esto hace que no necesites un método que retorne el cifrado en forma de File.
//                    */
//                    //File LlaveAESCifrada = new File(new String(encrypted));
//                    System.out.println("Done");
//                    break;
//
//                case 2:
//
//                    kname = Ventanas.entradaS("Ingrese el nombre del archivo de la llave AES a descifrar");
//                    llaveAES = Base64.getDecoder().decode(getFile("CifradoRSA/", kname + ".txt"));
//                    System.out.println(llaveAES);
//
//                    //Obtenemos en forma de variable PrivateKey la llave privada con la que descifraremos la llave AES
//                    llaveprivada = JOptionPane.showInputDialog("Ingrese nombre del archivo de llave privada");
//                    privkey = getPrivate("Llaves/" + llaveprivada + ".txt");
//                    System.out.println(privkey);
//
//                    //Parte que se encarga de cifrar el contenido de llaveAESCifrado con la llave privada
//                    decrypted = DescifrarRSA(privkey, llaveAES);
//                    System.out.println(decrypted);
//
//                    archllave = JOptionPane.showInputDialog("Ingrese nombre para guardar el archivo descifrado");
//                    saveFile(Base64.getEncoder().encode(decrypted), "DescifradoRSA/", archllave);
//                    
//                    /*
//                    La linea de abajo sirve para crear un File a partir del arreglo encrypted.
//                    Esto hace que no necesites un método que retorne el cifrado en forma de File.
//                    */
//                    //File LlaveAESCifrada = new File(new String(decrypted));
//                    System.out.println("Done");
//                    break;
//                default:
//                    exit(0);
//            }
//        } while (opc != 3);
//    }
}
