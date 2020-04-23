package main.java.org.illiam.uokms;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.*;
import java.util.HashMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.logging.Level;
import java.util.logging.Logger;

public class KeyManager {

    private static Logger LOG = Logger.getLogger(KeyManager.class.getName());

    private static int bitSize = 1024;
    private static DSAParameterSpec dsaParameterSpec;

    private static ReadWriteLock rwLock;
    private static HashMap<String, KeyPair> clients;

    private static KeyManagementServer kms;

    private static boolean testRun = false;

    public static void main(String[] args) {
        try {
            parseArgs(args);

            initializeEnvironment(bitSize);
            initializeClientStorage();

            if (testRun) {
                test();
                return;
            }

            startKeyManagementServer();

        } catch (Exception ex) {
            LOG.severe(String.format("Error: %s", ex.getMessage()));
        }
    }

    private static void initializeClientStorage() {
        rwLock = new ReentrantReadWriteLock();
        clients = new HashMap<>();
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

        } catch (InvalidParameterSpecException | NoSuchAlgorithmException | InvalidParameterException ex) {
            LOG.severe(String.format("Error, exiting: %s", ex.getMessage()));
            System.exit(1);
        }
    }

    private static void parseArgs(String[] args) {
        int MAX_ARGS = 2;

        if (args.length <= 0) {
            LOG.info(String.format("Using standard bit size %d", bitSize));
            return;
        }

        if (args.length > MAX_ARGS) {
            LOG.severe(String.format("Too many arguments encountered. Expected at most %d, got %d", MAX_ARGS, args.length));
            System.exit(1);
        }

        for (String arg : args) {
            if (arg.equals("test")) {
                testRun = true;
            }
        }

        if (testRun) {
            LOG.info("This is a test run of the KMS");
        }

        for (String arg : args) {
            try {
                bitSize = Integer.parseInt(arg);
            } catch (NumberFormatException ignored) { }
        }

        LOG.info(String.format("Using bit size: %d", bitSize));
    }

    public static AlgorithmParameterSpec GetDomainParameters() {
        return dsaParameterSpec;
    }

    public static boolean EnrollClient(String name) {
        try {
            // We may need to lock dsaParameterSpec here.
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
            kpg.initialize(dsaParameterSpec);

            KeyPair kp = kpg.generateKeyPair();
            DSAPublicKey publicKey = (DSAPublicKey) kp.getPublic();
            DSAPrivateKey privateKey = (DSAPrivateKey) kp.getPrivate();

            LOG.info(String.format("Successfully created the key pair for the client '%s'.", name));

            LOG.info("Checking the correctness of the generated values...");
            if (!dsaParameterSpec.getG().modPow(privateKey.getX(), dsaParameterSpec.getP()).equals(publicKey.getY())) {
                LOG.warning("Something's wrong with generated keys. Aborting...");
                return false;
            }

            LOG.info("The generated keys are correct! Enrolling the client...");
            updateClient(name, kp);
            LOG.info(String.format("The client '%s' was successfully enrolled!", name));

            return true;

        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException ex) {
            LOG.warning(String.format("Error enrolling a client '%s': %s", name, ex.getMessage()));
            return false;
        }
    }

    private static void updateClient(String name, KeyPair kp) {
        Lock writeLock = rwLock.writeLock();
        try {
            writeLock.lock();
            clients.put(name, kp);
        } finally {
            writeLock.unlock();
        }
    }

    public static PublicKey GetClientPublicKey(String name) {
        Lock readerLock = rwLock.readLock();
        try {
            readerLock.lock();
            if (!clients.containsKey(name)) {
                return null;
            }

            return clients.get(name).getPublic();

        } finally {
            readerLock.unlock();
        }
    }

    private static void startKeyManagementServer() {
        kms = new KeyManagementServer();
        kms.Start();
    }

    public static void Log(Level level, String err) {
        LOG.log(level, err);
    }

    /***
     * This is a testing section.
     * TODO: Enhance with more complex cases.
     ***/
    private static void test() {
        String dummy = "lalala";

        if (EnrollClient(dummy)) {
            DSAPublicKey publicKey = (DSAPublicKey) GetClientPublicKey(dummy);
            LOG.info(String.format("Successfully retrieved client's '%s' public key: %s",
                    dummy, publicKey.getY().toString()));
        } else {
            LOG.warning(String.format("Enrolling of a client '%s' failed!", dummy));
        }
    }
}
