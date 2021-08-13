package com.example;

import javax.crypto.Cipher;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class Server {

    private static PrivateKey privateKey;


    public static void main(String[] args) {
        DataInputStream dataInputStream = null;
        ServerSocket serverSocket = null;
        DataOutputStream dataOutputStream = null;
        BufferedReader bufferReader = null;
        privateKey = (PrivateKey) Crypt.keys.get("private");
        try {
            serverSocket = new ServerSocket(8088);
            System.out.println("Server is Waiting for client request... ");

            Socket socket = serverSocket.accept();
            dataInputStream = new DataInputStream(socket.getInputStream());

            OutputStream outputStream = socket.getOutputStream();
            dataOutputStream = new DataOutputStream(outputStream);

            bufferReader = new BufferedReader(new InputStreamReader(System.in));

            String str = "", strToClient = "";
            while (!str.equals("exit")) {
                str = dataInputStream.readUTF();
                String clientIp = (((InetSocketAddress) socket.getRemoteSocketAddress()).getAddress()).toString().replace("/", "");
                String descryptedText = decryptMessage(str, Crypt.publicKey);
                System.out.println(clientIp + " said: " + descryptedText);
                strToClient = bufferReader.readLine();
                String encryptedText = encryptMessage(strToClient, privateKey);
                dataOutputStream.writeUTF(encryptedText);
                dataOutputStream.flush();
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
                if (serverSocket != null) {
                    serverSocket.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private static Map<String,Object> getRSAKeys() throws Exception {
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
    private static String encryptMessage(String plainText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
    }
}
