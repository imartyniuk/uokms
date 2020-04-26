package main.java.org.illiam.uokms;

import org.json.simple.JSONObject;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.*;
import java.time.LocalTime;
import java.util.*;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.logging.Level;
import java.util.logging.Logger;

public class KeyManager {

    /**
     * Config section.
     * */
    private static final String configFile = "kms_config.json";
    private static final String portName = "port";
    private static final String stsHostName = "stsHost";
    private static final String stsPortName = "stsPort";
    private static final String runPeriodName = "runPeriod";
    private static final String updPeriodName = "updPeriod";

    /**
     * Logging section.
     * */
    private static Logger LOG = Logger.getLogger(KeyManager.class.getName());

    /**
     * Input arg defaults.
     * */
    private static int bitSize = 1024;
    private static boolean testRun = false;

    /**
     * Data, stored on the MKS.
     * */
    private static ReadWriteLock rwLock;
    private static HashMap<String, KeyPair> clients;
    private static HashMap<String, LocalTime> lastUpdated;
    private static HashMap<String, Long> publicKeyRevision;
    private static HashSet<String> keysBeingUpdated;

    /**
     * Server instance.
     * */
    private static KeyManagementServer kms;

    /**
     * Domain parameters.
     * */
    private static DSAParameterSpec dsaParameterSpec;

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
        lastUpdated = new HashMap<>();
        publicKeyRevision = new HashMap<>();
        keysBeingUpdated = new HashSet<>();
    }

    private static void initializeEnvironment(int bitSize) {
        try {
            AlgorithmParameterGenerator apg =
                    AlgorithmParameterGenerator.getInstance("DSA");
            apg.init(bitSize);
            AlgorithmParameters params = apg.generateParameters();

            dsaParameterSpec = params.getParameterSpec(DSAParameterSpec.class);

            LOG.info("Public domain is generated. Checking correctness...");
            if (OPOracle.ValidateDomainParameters(dsaParameterSpec)) {
                LOG.info("Domain parameters are valid!");
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

    /**
     * Client enrollment section.
     * */

    public static AlgorithmParameterSpec GetDomainParameters() {
        Lock readLock = rwLock.readLock();
        try {
            readLock.lock();
            DSAParameterSpec dsaPS = new DSAParameterSpec(
                    dsaParameterSpec.getP(), dsaParameterSpec.getQ(), dsaParameterSpec.getG());
            return dsaPS;
        } finally {
            readLock.unlock();
        }
    }

    public static boolean EnrollClient(String name) {
        try {

            KeyPair kp = GenKeyPair();
            LOG.info(String.format("Successfully created the key pair for the client '%s'.", name));

            UpdateClient(name, kp);
            LOG.info(String.format("The client '%s' was successfully enrolled!", name));

            return true;

        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeyException ex) {
            LOG.warning(String.format("Error enrolling a client '%s': %s", name, ex.getMessage()));
            return false;
        }
    }

    public static KeyPair GenKeyPair()
            throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException {
        DSAParameterSpec dsaParamSpec = (DSAParameterSpec) GetDomainParameters();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
        kpg.initialize(dsaParamSpec);
        KeyPair kp = kpg.generateKeyPair();

        LOG.info("Checking the correctness of the generated keys...");
        if (OPOracle.ValidateKeyPair(dsaParamSpec, kp)) {
            LOG.info("The generated keys are correct!");
        }

        return kp;
    }

    public static void UpdateClient(String name, KeyPair kp) {
        Lock writeLock = rwLock.writeLock();
        try {
            writeLock.lock();

            clients.put(name, kp);
            lastUpdated.put(name, LocalTime.now());

            long revision = publicKeyRevision.getOrDefault(name, (long) 0);
            publicKeyRevision.put(name, revision + 1);

        } finally {
            writeLock.unlock();
        }
    }

    private static KeyPair getClientKeyPair(String name) {
        Lock readerLock = rwLock.readLock();
        try {
            readerLock.lock();
            if (!clients.containsKey(name)) {
                return null;
            }

            return clients.get(name);

        } finally {
            readerLock.unlock();
        }
    }

    /**
     * Client section used for decryption.
     * */

    public static PublicKey GetClientPublicKey(String name) {
        if (isBeingUpdated(name)) {
            return null;
        }

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

    public static BigInteger RetrieveClientKey(String name, BigInteger U) {
        if (isBeingUpdated(name)) {
            return null;
        }

        Lock readerLock = rwLock.readLock();
        try {
            readerLock.lock();
            if (!clients.containsKey(name)) {
                return null;
            }

            DSAPrivateKey privKey = (DSAPrivateKey) clients.get(name).getPrivate();
            return U.modPow(privKey.getX(), dsaParameterSpec.getP());

        } finally {
            readerLock.unlock();
        }
    }

    /**
     * Section used by the KeyUpdater.
     * */

    public static BigInteger GenDelta(String name, KeyPair newKeyPair) {
        DSAParameterSpec dsaParameterSpec = (DSAParameterSpec) GetDomainParameters();
        KeyPair oldKeyPair = getClientKeyPair(name);

        BigInteger oldKey = ((DSAPrivateKey) oldKeyPair.getPrivate()).getX();
        BigInteger newKey = ((DSAPrivateKey) newKeyPair.getPrivate()).getX();

        return oldKey.multiply(newKey.modInverse(dsaParameterSpec.getQ())).mod(dsaParameterSpec.getQ());
    }

    public static Object[] GetClients() {
        Lock readerLock = rwLock.readLock();
        try {
            readerLock.lock();
            return clients.keySet().toArray().clone();
        } finally {
            readerLock.unlock();
        }
    }

    public static long GetPublicKeyRevision(String name) {
        Lock readerLock = rwLock.readLock();
        try {
            readerLock.lock();
            return publicKeyRevision.getOrDefault(name, (long) 0);

        } finally {
            readerLock.unlock();
        }
    }

    public static LocalTime GetLastUpdated(String name) {
        Lock readerLock = rwLock.readLock();
        try {
            readerLock.lock();
            if (!lastUpdated.containsKey(name)) {
                return null;
            }

            return lastUpdated.get(name);

        } finally {
            readerLock.unlock();
        }
    }

    public static void SetUpdateState(String name, boolean startUpdating) {
        Lock writeLock = rwLock.writeLock();
        try {
            writeLock.lock();
            if (startUpdating) {
                keysBeingUpdated.add(name);
            } else {
                keysBeingUpdated.remove(name);
            }
        } finally {
            writeLock.unlock();
        }
    }

    private static boolean isBeingUpdated(String name) {
        Lock readLock = rwLock.readLock();
        try {
            readLock.lock();
            return keysBeingUpdated.contains(name);
        } finally {
            readLock.unlock();
        }
    }


    /**
     * Main server section.
     * */

    private static void startKeyManagementServer() {
        JSONObject jsonObject = ConfigLoader.LoadConfig(configFile);

        long port = (long) jsonObject.get(portName);
        String stsHost = (String) jsonObject.get(stsHostName);
        long stsPort = (long) jsonObject.get(stsPortName);
        long runPeriod = (long) jsonObject.get(runPeriodName);
        long updPeriod = (long) jsonObject.get(updPeriodName);

        kms = new KeyManagementServer((int)port, stsHost, (int)stsPort, (int)runPeriod, (int)updPeriod);
        kms.Start();
    }

    public static void Log(Level level, String err) {
        LOG.log(level, err);
    }

    /***
     * Testing section.
     * TODO: Enhance with more complex cases.
     ***/
    private static void test() {
        String dummy = "lalala";
        try {
            if (EnrollClient(dummy)) {
                DSAPublicKey publicKey = (DSAPublicKey) GetClientPublicKey(dummy);
                LOG.info(String.format("Successfully retrieved client's '%s' public key: %s",
                        dummy, publicKey.getY().toString()));

                KeyPair initialKeyPair = KeyManager.getClientKeyPair(dummy);
                DSAPublicKey initialPub = (DSAPublicKey) initialKeyPair.getPublic();
                DSAPrivateKey initialPriv = (DSAPrivateKey) initialKeyPair.getPrivate();

                BigInteger r = genEncryptionKey();
                BigInteger initialW = dsaParameterSpec.getG().modPow(r, dsaParameterSpec.getP());
                BigInteger initialEnc = initialPub.getY().modPow(r, dsaParameterSpec.getP());
                BigInteger initialPow = initialW.modPow(initialPriv.getX(), dsaParameterSpec.getP());

                BigInteger oldW = initialW;
                for (int i = 0; i < 5; ++i) {
                    KeyPair newKeyPair = KeyManager.GenKeyPair();
                    KeyPair oldKeyPair = KeyManager.getClientKeyPair(dummy);
                    BigInteger delta = KeyManager.GenDelta(dummy, newKeyPair);
                    DSAPublicKey oldPub = (DSAPublicKey) oldKeyPair.getPublic();
                    DSAPublicKey newPub = (DSAPublicKey) newKeyPair.getPublic();
                    DSAPrivateKey oldPriv = (DSAPrivateKey) oldKeyPair.getPrivate();
                    DSAPrivateKey newPriv = (DSAPrivateKey) newKeyPair.getPrivate();

                    LOG.info(String.format("Generated delta:\n%s", delta));
                    //LOG.info(String.format("Generated private:\n%s", newPriv.getX().toString()));
                    //LOG.info(String.format("Old private:\n%s", oldPriv.getX().toString()));
                    //LOG.info(String.format("Generated public:\n%s", newPub.getY().toString()));
                    //LOG.info(String.format("Old public:\n%s", oldPub.getY().toString()));

                    BigInteger mult = newPub.getY().modPow(delta, dsaParameterSpec.getP());
                    LOG.info(String.format("New public to delta:\n%s", mult.toString()));
                    if (mult.equals(oldPub.getY())) {
                        LOG.info("OK!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
                    } else {
                        LOG.severe("NO>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
                    }

                    BigInteger newW = oldW.modPow(delta, dsaParameterSpec.getP());
                    if (newW.modPow(newPriv.getX(), dsaParameterSpec.getP()).equals(initialPow)) {
                        LOG.info("AGAIN OK!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
                    } else {
                        LOG.severe("AGAIN NO>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
                    }

                    BigInteger rr = genEncryptionKey();
                    //LOG.info(String.format("This is r:\n%s", r.toString()));
                    //LOG.info(String.format("This is rr:\n%s", rr.toString()));

                    BigInteger u = newW.modPow(rr, dsaParameterSpec.getP());
                    //LOG.info(String.format("This is u:\n%s", u.toString()));

                    BigInteger v = u.modPow(newPriv.getX(), dsaParameterSpec.getP());
                    //LOG.info(String.format("This is v:\n%s", v.toString()));

                    BigInteger rrInverse = rr.modInverse(dsaParameterSpec.getQ());
                    //LOG.info(String.format("This is inverse to rr:\n%s", rrInverse.toString()));

                    BigInteger newEnc = v.modPow(rrInverse, dsaParameterSpec.getP());
                    LOG.info(String.format("Old enc:\n%s", initialEnc.toString()));
                    LOG.info(String.format("New enc:\n%s", newEnc.toString()));

                    if (newEnc.equals(initialEnc)) {
                        LOG.info("AGAIN AGAIN OK!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
                    } else {
                        LOG.severe("AGAIN AGAIN NO>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
                    }

                    UpdateClient(dummy, newKeyPair);
                    oldW = newW;
                }


            } else {
                LOG.warning(String.format("Enrolling of a client '%s' failed!", dummy));
            }
        } catch(Exception ex) {}
    }

    private static BigInteger genEncryptionKey() {
        int qBitLen = dsaParameterSpec.getQ().bitCount();
        Random rnd = new Random();
        int bitLen = rnd.nextInt(qBitLen);
        while(bitLen < qBitLen / 2) { bitLen = rnd.nextInt(qBitLen); }

        return BigInteger.probablePrime(bitLen, new Random());
    }
}
