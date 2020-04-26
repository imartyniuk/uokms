package main.java.org.illiam.uokms;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAParameterSpec;

public class OPOracle {

    public static boolean ValidateDomainParameters(DSAParameterSpec dsaParameterSpec) throws InvalidParameterException {
        if (dsaParameterSpec == null) {
            throw new InvalidParameterException("Domain parameters must not be null");
        }

        if (!dsaParameterSpec.getG().modPow(dsaParameterSpec.getQ(), dsaParameterSpec.getP()).equals(BigInteger.ONE)) {
            throw new InvalidParameterException("G to the power of Q must be equal to 1");
        }

        if (!dsaParameterSpec.getP().subtract(BigInteger.ONE).mod(dsaParameterSpec.getQ()).equals(BigInteger.ZERO)) {
            throw new InvalidParameterException("Domain prime P - 1 must be divisible by the subprime Q");
        }

        return true;
    }

    public static boolean ValidateKeyPair(DSAParameterSpec dsaParameterSpec, KeyPair keyPair) throws InvalidKeyException {
        DSAPublicKey publicKey = (DSAPublicKey) keyPair.getPublic();
        DSAPrivateKey privateKey = (DSAPrivateKey) keyPair.getPrivate();

        if (!dsaParameterSpec.getG().modPow(privateKey.getX(), dsaParameterSpec.getP()).equals(publicKey.getY())) {
            throw new InvalidKeyException("Group generator to the power of private key does not equal to the public key");
        }

        return true;
    }
}
