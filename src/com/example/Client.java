package com.example;

import javax.crypto.Cipher;
import java.io.*;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class Client {

    private static PrivateKey privateKey;

    public static void main(String[] args) throws Exception {
        Socket socket = null;
        DataInputStream dataInputStream = null;
        DataOutputStream dataOutputStream = null;
        BufferedReader bufferReader = null;
        privateKey = (PrivateKey) Crypt.keys.get("private");

        try {
            socket = new Socket("localhost", 8088);
            dataInputStream = new DataInputStream(socket.getInputStream());

            OutputStream outputStream = socket.getOutputStream();
            dataOutputStream = new DataOutputStream(outputStream);

            bufferReader = new BufferedReader(new InputStreamReader(System.in));

            String strFromServer = "", strToClient = "";
            while (!strFromServer.equals("exit")) {
                strFromServer = bufferReader.readLine();
                String encryptedText = encryptMessage(strFromServer, privateKey);
                dataOutputStream.writeUTF(encryptedText);
                dataOutputStream.flush();
                strToClient = dataInputStream.readUTF();
                String descryptedText = decryptMessage(strToClient, Crypt.publicKey);
                System.out.println("Server said: " + descryptedText);
            }

        } catch (Exception exe) {
            exe.printStackTrace();
        } finally {
            try {

                if (bufferReader != null) {
                    bufferReader.close();
                }

                if (dataInputStream != null) {
                    dataInputStream.close();
                }

                if (dataOutputStream != null) {
                    dataOutputStream.close();
                }
                if (socket != null) {
                    socket.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private static String encryptMessage(String plainText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
    }

    private static Map<String, Object> getRSAKeys() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        Map<String, Object> keys = new HashMap<>();
        keys.put("private", privateKey);
        keys.put("public", publicKey);
        return keys;
    }
    private static String decryptMessage(String encryptedText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedText)));
    }
}
