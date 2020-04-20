import javax.crypto.KeyGenerator;
import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.util.logging.Logger;

public class KeyManager {

    private static Logger LOG = Logger.getLogger(KeyManager.class.getName());
    private static int bitSize = 1024;
    private static DSAParameterSpec dsaParameterSpec;

    public static void main(String[] args) {
        parseArgs(args);

        initializeEnvironment(bitSize);
    }

    private static void initializeEnvironment(int bitSize) {
        try {
            AlgorithmParameterGenerator apg =
                    AlgorithmParameterGenerator.getInstance("DSA");
            apg.init(bitSize);
            AlgorithmParameters params = apg.generateParameters();

            dsaParameterSpec = params.getParameterSpec(DSAParameterSpec.class);

            LOG.info("Public domain is generated. Checking correctness...");

            if (!dsaParameterSpec.getP().subtract(BigInteger.ONE).mod(dsaParameterSpec.getQ()).equals(BigInteger.ZERO)) {
                throw new InvalidParameterException("Domain prime P - 1 must be divisible by the subprime Q");
            } else {
                LOG.info("Domain parameters were generated successfully!");
            }

        } catch (InvalidParameterSpecException | InvalidParameterException | NoSuchAlgorithmException ex) {
            LOG.severe(String.format("Error, exiting: %s", ex.getMessage()));
            System.exit(1);
        }
    }

    private static void parseArgs(String[] args) {
        if (args.length == 1) {
            bitSize = Integer.parseInt(args[0]);
            LOG.info(String.format("Using custom bit size: %d", bitSize));
        } else {
            LOG.info(String.format("Using standard bit size %d", bitSize));
        }
    }

    private DSAParameterSpec exposeDomainParameters() {
        return dsaParameterSpec;
    }
}
