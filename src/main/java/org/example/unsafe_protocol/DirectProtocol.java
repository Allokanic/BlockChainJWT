package org.example.unsafe_protocol;

import org.bouncycastle.util.encoders.Hex;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;

import java.math.BigInteger;

public class DirectProtocol {
    public static MyCustomSignature encryptMessage(String msg, BigInteger privateKey) {
        BigInteger publicKey = Sign.publicKeyFromPrivate(privateKey);
        ECKeyPair keyPair = new ECKeyPair(privateKey, publicKey);

        byte[] msgHash = Hash.sha3(msg.getBytes());
        Sign.SignatureData signature = Sign.signMessage(msgHash, keyPair, false);
        System.out.println("\tMsg hash: " + Hex.toHexString(msgHash));
        System.out.printf("""
                        Signature:
                            v = %d,
                            r = %s (len = %d),
                            s = %s (len = %d)
                        """,
                signature.getV() - 27,
                Hex.toHexString(signature.getR()), Hex.toHexString(signature.getR()).length(),
                Hex.toHexString(signature.getS()), Hex.toHexString(signature.getS()).length());
        return new MyCustomSignature(msg, signature.getR(), signature.getS(), signature.getV());
    }

    public static Boolean validateMessage(MyCustomSignature myCustomSignature) {
        var signature = new Sign.SignatureData(
                myCustomSignature.getV(),
                myCustomSignature.getR(),
                myCustomSignature.getS());
        try {
            var pubKeyRecovered = Sign.signedMessageToKey(myCustomSignature.getMsg().getBytes(), signature);
            System.out.println("\tRecovered public key: " + pubKeyRecovered.toString(16));
            var recoveredAddress = "0x" + Keys.getAddress(pubKeyRecovered);
            System.out.println("\tRecovered address: " + recoveredAddress);
            return recoveredAddress.equals(myCustomSignature.getMsg());
        } catch (Exception e) {
            return false;
        }
    }
}
