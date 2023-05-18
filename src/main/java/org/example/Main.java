package org.example;

import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;

import java.math.BigInteger;
import java.util.Arrays;

import static org.example.unsafe_protocol.DirectProtocol.encryptMessage;
import static org.example.unsafe_protocol.DirectProtocol.validateMessage;
import static org.example.safe_protocol.PrivateProtocol.getSignature;
import static org.example.safe_protocol.PrivateProtocol.validateSignature;

public class Main {

    public static void main(String[] args) {
        System.out.println("INIT");
        BigInteger privateKey;
        try {
            privateKey = Keys.createEcKeyPair().getPrivateKey();
        } catch (Exception e) {
            return;
        }
        BigInteger publicKey = Sign.publicKeyFromPrivate(privateKey);
        var address = "0x" + Keys.getAddress(publicKey);
        System.out.println("\tPrivate key: " + privateKey.toString(16));
        System.out.println("\tPublic key: " + publicKey.toString(16));
        System.out.println("\tMsg: " + address + "\n");


        System.out.println("DIRECT PROTOCOL\nENCRYPT");
        var encryptedData = encryptMessage(address, privateKey);
        System.out.println("\nVALUE SENT");
        System.out.printf("\tr = %s\n\ts = %s\n\tv = %s",
                Arrays.toString(encryptedData.getR()),
                Arrays.toString(encryptedData.getS()),
                encryptedData.getV());
        System.out.println("\nDECRYPT");
        System.out.println("\tVALIDATED: " + validateMessage(encryptedData) + "\n");


        System.out.println("PRIVATE PROTOCOL\nENCRYPT");
        var privateEncryptedData = getSignature(address, privateKey);
        System.out.println("\nVALUE SENT");
        System.out.println("\trsv = " + privateEncryptedData.getSignature());
        System.out.println("\nDECRYPT");
        System.out.println("\tVALIDATED " + validateSignature(privateEncryptedData));
    }
}
