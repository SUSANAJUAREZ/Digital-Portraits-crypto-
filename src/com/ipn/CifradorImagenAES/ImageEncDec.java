package com.ipn.CifradorImagenAES;

/**
 *
 * @author yeyof
 */
import com.ipn.util.Ventanas;
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
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Base64;
import javax.crypto.KeyGenerator;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JOptionPane;
//import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

public class ImageEncDec {

    /*
    getFile() es un método que lee el contenido de cualquier archivo y te lo regresa 
    como un arreglo de bytes para que tú lo puedas manejar a tu antojo. 
    Esto lo hace para que puedas hacer Cast a prácticamente cualquier 
    tipo de variable, pasarlo a String y demás. 
    Recibe como parámetros 2 String: ruta del archivo y nombre del archivo
     */
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
            cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(new byte[16]));
            encrypted = cipher.doFinal(content);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return encrypted;

    }
    
    /*
    encryptPdfFile() sirve para cifrar la imagen en modo CTR usando AES sin padding.
    Recibe como parametros un File(que es el archivo llave con el cual vas a cifrar)
    y un arreglo de bytes (que es el contenido de la imagen pero en bytes. Para esto antes se debió
    de haber leido el archivo imagen con el método getFile()).
    */
    public static byte[] encryptPdfFile(File llave, byte[] content) {
        Cipher cipher;
        byte[] encrypted = null;
        SecretKey key;
        Path dir;
        try {
            dir = Paths.get(llave.getPath());
            //System.out.println(dir);
            key = new SecretKeySpec(Files.readAllBytes(dir), 0, Files.readAllBytes(dir).length, "AES");
            cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(new byte[16]));
            encrypted = cipher.doFinal(content);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return encrypted;
    }
    
    
    /*
    decryptPdfFile() sirve para descifrar la imagen en modo CTR usando AES sin padding.
    Recibe como parametros un File(que es el archivo llave con el cual vas a descifrar)
    y un arreglo de bytes (que es el contenido de la imagen cifrada pero en bytes. Para esto antes se debió
    de haber leido el archivo imagen con el método getFile()).
    */
    public static byte[] decryptPdfFile(File llave, byte[] textCryp) {
        Cipher cipher;
        byte[] decrypted = null;
        SecretKey key;
        Path dir;
        try {
            dir = Paths.get(llave.getPath());
            //System.out.println(dir);
            key = new SecretKeySpec(Files.readAllBytes(dir), 0, Files.readAllBytes(dir).length, "AES");
            cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(new byte[16]));
            decrypted = cipher.doFinal(textCryp);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return decrypted;
    }

    public static byte[] decryptPdfFile(SecretKey key, byte[] textCryp) {
        Cipher cipher;

        byte[] decrypted = null;
        try {
            cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(new byte[16]));
            decrypted = cipher.doFinal(textCryp);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return decrypted;
    }
    
    
    /*
    saveFile() es un método que sirve para guardar cualquier arreglo de bytes en un archivo.
    Recibe como parámetros un arreglo de bytes(que es el contenido del archivo, ya sea llave, texto o imagen
    pero en bytes), un String ruta (ruta donde se guardará el archivo) y otro String archivo(nombre con el
    que se guardará el archivo)
    */
    public static void saveFile(byte[] bytes, String path, String archivo) throws IOException {

        FileOutputStream fos = new FileOutputStream(path + archivo);
        fos.write(bytes);
        fos.close();

    }

    
    /*
    writeToFile() es el método que permite escribir la llave en un archivo.
    Recibe solo 2 parámetros: String path (que es la ruta donde se guardará el archivo)
    y un arreglo de bytes 'key'(se recibe la llave en forma de bytes para poder
    darle otro tipo de codificacion (base64 o el que desee) y de ahí escribirla al archivo)
    */
    public static void writeToFile(String path, byte[] key) throws IOException {

        File f = new File(path);
        f.getParentFile().mkdirs();

        FileOutputStream fos = new FileOutputStream(f);
        fos.write(key);
        fos.flush();
        fos.close();
    }

    /*
    LeerLlave() lo que hace es leer el contenido del archivo llave, 
    para de ahí generar una SecretKey (tipo de variable necesaria para poder cifrar o descifrar la imagen). 
    Recibe como parámetro un String que es el nombre (sin extensión) del archivo llave que quieres leer.
     */
    private static SecretKey leerllave(String kname) {
        byte[] encodedkey = null;
        SecretKey key = null;
        try {
            encodedkey = getFile("LlavesAES/", kname + ".txt");
            key = new SecretKeySpec(encodedkey, "AES");
            System.out.println(key);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return key;
    }

    
    /*
    llavAES() sirve para generar una llave AES de longitud de 128 bits.
    Solo necesita como parámetro un String que es el nombre con el que se desea guardar el archivo llave.
    */
    public static File llaveAES(String nombrellave) throws NoSuchAlgorithmException, IOException, NoSuchProviderException {
        KeyGenerator keyGenerator;
        SecretKey key;
        File filellave = null;
        try {
            keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            key = keyGenerator.generateKey();
            System.out.println(key);
            writeToFile("LlavesAES/" + nombrellave + ".txt", Base64.getEncoder().encodeToString(key.getEncoded()).getBytes());
            filellave = new File("LlavesAES/" + nombrellave + ".txt");
        } catch (IOException ioe) {
        }
        return filellave;
    }
    
    
    /*
    public static void main(String args[])
            throws NoSuchAlgorithmException, InstantiationException, IllegalAccessException, IOException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleFipsProvider());
        File llave = null;
        SecretKey skey;
        String nombrearchivo, encarchivo, kname;
        byte[] content, encrypted, decrypted;
        int opc, opc2, rep;
        do {
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
                            llave = llaveAES(kname);

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
        } while (opc != 3);
    }
    */
}
