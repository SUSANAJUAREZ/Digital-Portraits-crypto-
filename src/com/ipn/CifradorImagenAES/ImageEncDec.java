package com.ipn.CifradorImagenAES;

/**
 *
 * @author yeyof
 */
import cipher.Ventanas;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import static java.lang.System.exit;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JOptionPane;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

public class ImageEncDec {

    public static byte[] getFile(String path, String archivo) {

        File f = new File(path + archivo);
        InputStream is = null;
        try {
            is = new FileInputStream(f);
        } catch (FileNotFoundException e2) {
            // TODO Auto-generated catch block
            e2.printStackTrace();
        }
        byte[] content = null;
        try {
            content = new byte[is.available()];
        } catch (IOException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }
        try {
            is.read(content);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return content;
    }

    public static byte[] encryptPdfFile(SecretKey key, byte[] content) {
        Cipher cipher;
        byte[] encrypted = null;
        try {
            cipher = Cipher.getInstance("AES/CTR/NoPadding", "BCFIPS");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(new byte[16]));
            encrypted = cipher.doFinal(content);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return encrypted;

    }

    public static byte[] encryptPdfFile(File llave, byte[] content) {
        Cipher cipher;
        byte[] encrypted = null;
        SecretKey key;
        Path dir;
        try {
            dir = Paths.get(llave.getPath());
            //System.out.println(dir);
            key = new SecretKeySpec(Files.readAllBytes(dir), 0, Files.readAllBytes(dir).length, "AES");
            cipher = Cipher.getInstance("AES/CTR/NoPadding", "BCFIPS");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(new byte[16]));
            encrypted = cipher.doFinal(content);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return encrypted;
    }

    public static byte[] decryptPdfFile(SecretKey key, byte[] textCryp) {
        Cipher cipher;
        byte[] decrypted = null;
        try {
            cipher = Cipher.getInstance("AES/CTR/NoPadding", "BCFIPS");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(new byte[16]));
            decrypted = cipher.doFinal(textCryp);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return decrypted;
    }

    public static void saveFile(byte[] bytes, String path, String archivoenc) throws IOException {

        FileOutputStream fos = new FileOutputStream(path + archivoenc);
        fos.write(bytes);
        fos.close();

    }

    public static void writeToFile(String path, byte[] key) throws IOException {

        File f = new File(path);
        f.getParentFile().mkdirs();

        FileOutputStream fos = new FileOutputStream(f);
        fos.write(key);
        fos.flush();
        fos.close();
    }

    private static SecretKey leerllave(String kname) {
        byte[] encodedkey = null;
        SecretKey key= null;
        try {
            encodedkey = getFile("LlavesAES/", kname + ".txt");
            key = new SecretKeySpec(encodedkey, "AES");
            System.out.println(key);
        } catch(Exception e){
            e.printStackTrace();
        }
       return key;
    }

    public static File llaveRSA(String nombrellave) throws NoSuchAlgorithmException, IOException, NoSuchProviderException {
        KeyGenerator keyGenerator;
        SecretKey key;
        File filellave = null;
        try {
            keyGenerator = KeyGenerator.getInstance("AES", "BCFIPS");
            keyGenerator.init(128);
            key = keyGenerator.generateKey();
            System.out.println(key);
            writeToFile("LlavesAES/" + nombrellave + ".txt", key.getEncoded());
            filellave = new File("LlavesAES/" + nombrellave + ".txt");
        } catch (IOException ioe) {
        }
        return filellave;
    }

    public static void main(String args[])
            throws NoSuchAlgorithmException, InstantiationException, IllegalAccessException, IOException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleFipsProvider());
        File llave = null;
        SecretKey skey;
        String nombrearchivo, encarchivo, kname;
        byte[] content, encrypted, decrypted;
        int opc, opc2;
        System.out.println("--------Cifrador de imagen--------"
                + "\n 1.-Cifrar imagen\n"
                + "2.-Descifrar imagen\n"
                + "3.-Salir");
        opc = Ventanas.entradaI("Seleccione una opcion");
        switch (opc) {
            case 1:
                System.out.println("\n\n--------Cifrador de imagen--------"
                        + "\n1.-Generar llave\n"
                        + "2.-Tengo una llave");
                opc2 = Ventanas.entradaI("Ingrese opcion");
                switch (opc2) {
                    case 1:
                        kname = Ventanas.entradaS("Ingrese el nombre del archivo de la llave");
                        llave = llaveRSA(kname);

                        nombrearchivo = JOptionPane.showInputDialog("Ingrese nombre de la imagen");

                        content = getFile("Img/", nombrearchivo);
                        System.out.println(content);

                        encrypted = encryptPdfFile(llave, content);
                        System.out.println(encrypted);

                        encarchivo = JOptionPane.showInputDialog("Ingrese nombre de archivo cifrado");
                        saveFile(encrypted, "ImgEnc/", encarchivo);
                        System.out.println("Done");
                        break;
                    
                    case 2:
                        kname = Ventanas.entradaS("Ingrese el nombre del archivo de la llave");
                        skey = leerllave(kname);

                        nombrearchivo = JOptionPane.showInputDialog("Ingrese nombre de la imagen");

                        content = getFile("Img/", nombrearchivo);
                        System.out.println(content);

                        encrypted = encryptPdfFile(skey, content);
                        System.out.println(encrypted);

                        encarchivo = JOptionPane.showInputDialog("Ingrese nombre para guardar el archivo cifrado");
                        saveFile(encrypted, "ImgEnc/", encarchivo);
                        System.out.println("Done");
                        break;
                     
                    default:
                        exit(0);
                }
                break;

            case 2:
                encarchivo = JOptionPane.showInputDialog("Ingrese nombre de la imagen cifrada");

                content = getFile("ImgEnc/", encarchivo);
                System.out.println(content);

                kname = Ventanas.entradaS("Ingrese el nombre del archivo llave");
                skey = leerllave(kname);

                decrypted = decryptPdfFile(skey, content);
                System.out.println(decrypted);

                nombrearchivo = JOptionPane.showInputDialog("Ingrese nombre para guardar el archivo descifrado");
                saveFile(decrypted, "Img/", nombrearchivo);
                System.out.println("Done");
                break;
            default:
                exit(0);
        }
    }
}
