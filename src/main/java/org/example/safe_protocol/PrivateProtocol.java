package org.example.safe_protocol;

import org.bouncycastle.util.encoders.Hex;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;

import java.math.BigInteger;

public class PrivateProtocol {
    public static MyCustomWrappedSignature getSignature(String msg, BigInteger privateKey) {
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
                signature.getV(),
                Hex.toHexString(signature.getR()), Hex.toHexString(signature.getR()).length(),
                Hex.toHexString(signature.getS()), Hex.toHexString(signature.getS()).length());
        return new MyCustomWrappedSignature(
                msg,
                Hex.toHexString(signature.getR()) +
                        Hex.toHexString(signature.getS()) +
                        Hex.toHexString(new byte[]{signature.getV()})
        );
    }

    public static Boolean validateSignature(MyCustomWrappedSignature myCustomSignature) {
        var vrs = myCustomSignature.getSignature();
        var r = Hex.decode(vrs.substring(0, 64));
        var s = Hex.decode(vrs.substring(64, 128));
        var v = Byte.valueOf(vrs.substring(128), 16);
        var signature = new Sign.SignatureData(v, r, s);
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
