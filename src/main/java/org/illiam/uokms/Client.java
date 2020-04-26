package main.java.org.illiam.uokms;

import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.spec.DSAParameterSpec;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

public class Client {

    /**
     * Mode section.
     * */
    private enum MODE {
        INTERACTIVE,
        SIMULATION
    };
    private final MODE mode;

    /**
     * Config section.
     * */
    private static final String configFile = "client_config.json";
    private static final String kmsHostName = "kmsHost";
    private static final String kmsPortName = "kmsPort";
    private static final String stsHostName = "stsHost";
    private static final String stsPortName = "stsPort";
    private static final String symAlgoName = "symEncAlgo";
    private static final String symAlgoDetailsName = "symEncAlgoDetails";
    private static final String hashAlgoName = "hashAlgo";
    private static final String hashKeyLenName = "hashKeyLen";

    /**
     * Logging section.
     * */
    private static Logger LOG = Logger.getLogger(Client.class.getName());

    /**
     * Communication constants.
     */
    private final String kmsHost;
    private final int kmsPort;
    private final String stsHost;
    private final int stsPort;

    /**
     * Crypto constants.
     * */
    private final String SYMMETRIC_ENCRYPTION_ALGO;
    private final String SYMMETRIC_ENCRYPTION_DETAILS;
    private final String HASH_ALGO;
    private final int HASH_KEY_LENGTH;

    /**
     * Client identification and communication fields.
     * */
    private UUID uuid;

    /**
     * Crypto fields.
     * */
    private DSAParameterSpec dsaParameterSpec;
    private BigInteger dsaPublicKey;
    private long publicKeyRevision;
    private boolean enrollmentStatus;

    private HashMap<String, IvParameterSpec> ivParameterSpecs;

    public static void main(String[] args) {
        MODE mode = getModeFromArgs(args);

        Client client = createClient(mode);
        client.runClient();
    }

    private Client(MODE mode,
                   String kmsHost, int kmsPort,
                   String stsHost, int stsPort,
                   String symEncAlgo, String symEncAlgoDetails,
                   String hashAlgo, int hashAlgoKeyLen) {
        this.kmsHost = kmsHost;
        this.kmsPort = kmsPort;
        this.stsHost = stsHost;
        this.stsPort = stsPort;

        this.SYMMETRIC_ENCRYPTION_ALGO = symEncAlgo;
        this.SYMMETRIC_ENCRYPTION_DETAILS = symEncAlgoDetails;
        this.HASH_ALGO = hashAlgo;
        this.HASH_KEY_LENGTH = hashAlgoKeyLen;

        this.mode = mode;
        uuid = UUID.randomUUID();
        ivParameterSpecs = new HashMap<>();

        LOG.info(String.format("Created a client with an id: %s", uuid.toString()));
    }

    private static Client createClient(MODE mode) {
        JSONObject jsonObject = ConfigLoader.LoadConfig(configFile);

        String kmsHost = (String) jsonObject.get(kmsHostName);
        long kmsPort = (long) jsonObject.get(kmsPortName);
        String stsHost = (String) jsonObject.get(stsHostName);
        long stsPort = (long) jsonObject.get(stsPortName);

        String symEncAlgo = (String) jsonObject.get(symAlgoName);
        String symEncAlgoDetails = (String) jsonObject.get(symAlgoDetailsName);
        String hashAlgo = (String) jsonObject.get(hashAlgoName);
        long hashAlgoKeyLen = (long) jsonObject.get(hashKeyLenName);

        Client client = new Client(mode,
                kmsHost, (int) kmsPort,
                stsHost, (int) stsPort,
                symEncAlgo, symEncAlgoDetails,
                hashAlgo, (int) hashAlgoKeyLen);
        return client;
    }

    private void runClient() {
        this.initializeClient();
        LOG.info("The client initialization is successful!");

         if (mode == MODE.SIMULATION) {
            this.runSimulationClient();
         } else {
             this.runInteractiveClient();
         }
    }

    private void runSimulationClient() {
        int numberOfObjets = 3;
        int objectLen = 10;

        HashMap<String, String> objects = new HashMap<>();

        // Generate random strings and store them.
        for (int i = 0; i < numberOfObjets; ++i) {
            String rndStr = genRandomString(objectLen);

            String id = this.storeObject(rndStr);
            if (id != null) {
                objects.put(rndStr, id);
            }
        }
        try {
            while (true) {
                Random rndSleep = new Random();
                int sleepingTime = rndSleep.nextInt(15);
                TimeUnit.SECONDS.sleep(sleepingTime);

                Random rndAction = new Random();
                int nextAction = rndAction.nextInt(10);

                // In 1 of out 10 cases we'll be creating a new random string.
                // 9 of 10 times we'll be reading the existing ones.
                if (nextAction < 1) {
                    LOG.info("Storing...");

                    String rndStr = genRandomString(objectLen);
                    String id = this.storeObject(rndStr);

                    if (id != null) {
                        objects.put(rndStr, id);
                    } else {
                        LOG.warning(String.format("Error storing a string: '%s'", rndStr));
                        if (!this.getPublicKey()) {
                            LOG.severe("Failed to update the public key!");
                        }

                        continue;
                    }

                } else {
                    LOG.info("Retrieving...");

                    Random rndObj = new Random();
                    int nexObj = rndObj.nextInt(objects.size());

                    String expectedStr = (String) objects.keySet().toArray()[nexObj];
                    String objId = objects.get(expectedStr);
                    IvParameterSpec ivParameterSpec = ivParameterSpecs.get(objId);

                    ClientInformation.ClientEntry entry = this.getObject(objId);
                    if (entry == null) {
                        LOG.severe("Did not retrieve from storage, aborting this simulation round");
                        continue;
                    }

                    BigInteger encKey = this.getObjectSpecificKey(entry);
                    if (encKey == null) {
                        LOG.severe("Did not retrieve the object-specific key, aborting this simulation round");
                        continue;
                    }

                    String decryptedObject = this.decryptWithKey(entry.encryptedObject, encKey, ivParameterSpec);
                    if (decryptedObject == null) {
                        LOG.severe("Failed to decrypt the object during this simulation");
                        System.exit(1);
                    }

                    if (!expectedStr.equals(decryptedObject)) {
                        LOG.warning(String.format(
                                "Received different decrypted message. Expected: '%s', got '%s'.", expectedStr, decryptedObject));
                        LOG.warning("This happens if the STS object is old, but the KMS public key is new.\n".
                                concat("This is possible when the events are executed in the following sequence:\n").
                                concat("GetObj -> UpdKey -> GetKey\n").
                                concat("Please, feel free to discard the object data and retry the process"));
                    }

                    LOG.info("This simulation run was successful!");
                }
            }
        } catch (InterruptedException ignore) {}
    }

    private void runInteractiveClient() {

    }

    private static MODE getModeFromArgs(String[] args) {
        if (args.length > 1) {
            LOG.severe("Client currently accepts only 1 argument, 'mode'.");
            System.exit(1);
        }

        // By default use INTERACTIVE mode;
        MODE mode = MODE.INTERACTIVE;
        if (args.length == 0) {
            return mode;
        }

        switch (args[0]) {
            case "-s":
                mode = MODE.SIMULATION;
                break;
            case "-i":
                mode = MODE.INTERACTIVE;
                break;
            default:
                LOG.severe(String.format(
                        "Expected '-s' for SIMULATION mode and '-i' for INTERACTIVE mode. Got '%s'", args[0]));
                System.exit(1);
        }

        return mode;
    }

    private void initializeClient() {
        try {
            dsaParameterSpec = (DSAParameterSpec) communicate(
                    kmsHost, kmsPort, genGetDomainParametersRequest(), processDomainParameters);
            if (OPOracle.ValidateDomainParameters(dsaParameterSpec)) {
                LOG.info("Successfully received valid domain parameters!");
            }

            enrollmentStatus = (boolean) communicate(
                    kmsHost, kmsPort, genEnrollClientRequest(), processEnrollClientResponse);
            if (!enrollmentStatus) {
                throw new InvalidParameterException("The client was not enrolled for KMS!");
            }
            LOG.info("The client was successfully enrolled for KMS!");

            if (!getPublicKey()) {
                throw new InvalidParameterException("The public key was not retrieved!");
            }
            LOG.info("The public key was retrieved successfully!");

            enrollmentStatus = (boolean) communicate(
                    stsHost, stsPort, genEnrollClientForStorageRequest(), processEnrollClientResponse);
            if (!enrollmentStatus) {
                throw new InvalidParameterException("The client was not enrolled for STS!");
            }
            LOG.info("The client was successfully enrolled for STS!");

        } catch (IOException | ParseException | NumberFormatException ex) {
            LOG.severe(String.format("Error initializing client: %s", ex.getMessage()));
            ex.printStackTrace();
            System.exit(1);
        }
    }

    private boolean getPublicKey() {
        try {
            String pubKeyResult = (String) communicate(kmsHost, kmsPort, genGetPublicKeyRequest(), processPublicKey);
            if (pubKeyResult.equals(OP.Error)) {
                return false;
            }

            dsaPublicKey = new BigInteger(pubKeyResult);
            return true;

        } catch (IOException | ParseException ex) {
            LOG.severe(String.format("Error getting a public key: %s", ex.getMessage()));
            ex.printStackTrace();
            return false;
        }
    }

    private BigInteger getObjectSpecificKey(ClientInformation.ClientEntry entry) {
        try {
            BigInteger rr = genEncryptionKey();
            BigInteger U = new BigInteger(entry.w).modPow(rr, dsaParameterSpec.getP());

            String v = (String) communicate(kmsHost, kmsPort, genRetrieveKeyRequest(U), processRetrieveKey);
            if (v.equals(OP.Error)) {
                return null;
            }
            LOG.info("The object-specific key was retrieved successfully!");

            BigInteger V = new BigInteger(v);
            BigInteger rrInverse = rr.modInverse(dsaParameterSpec.getQ());

            return V.modPow(rrInverse, dsaParameterSpec.getP());

        } catch (IOException | ParseException | NumberFormatException ex) {
            LOG.severe(String.format("Error retrieving the object-specific key: %s", ex.getMessage()));
            return null;
        }
    }

    /**
     * Returns the String representation of an Object ID.
     * */
    private String storeObject(String obj) {
        try {
            String objId  = (String) communicate(
                    stsHost, stsPort, genWriteStorageEntryRequest(obj), processWriteStorageEntryResponse);
            if (objId != null) {
                LOG.info("The object was stored successfully.");
            }

            return objId;

        } catch (IOException | ParseException | InvalidKeyException | IllegalArgumentException ex) {
            LOG.severe(String.format("Error storing a message: %s", ex.getMessage()));
            ex.printStackTrace();

            return null;
        }
    }

    private ClientInformation.ClientEntry getObject(String objId) {
        try {
            LOG.info(String.format("Getting object: '%s'", objId));
            ClientInformation.ClientEntry entry = (ClientInformation.ClientEntry) communicate(
                            stsHost, stsPort, genReadStorageEntryRequest(objId), processReadStorageEntryResponse);

            if (entry == null) {
                LOG.warning(String.format("Failed to retrieve the object: '%s'", objId));
                return null;
            }

            LOG.info("Successfully received an object from storage!");
            LOG.info(String.format("Object ID: '%s'", entry.objId));
            LOG.info(String.format("Encrypted object: '%s'", entry.encryptedObject));

            return entry;

        } catch (IOException | ParseException ex) {
            LOG.severe(String.format("Error reading an object: %s", ex.getMessage()));
            return null;
        }
    }

    private Object communicate(String host, int port, String request, IResponseProcessor processor)
            throws IOException, ParseException {
        Socket socket = new Socket(host, port);

        Communicator.SendMessage(socket, request);
        String response = Communicator.ReceiveMessage(socket);

        socket.close();

        return processor.ProcessResponse(response);
    }

    /**
     * Domain parameters section.
     * */

    private IResponseProcessor processDomainParameters = (response) -> {
        try {
            JSONObject jsonObject = JsonParser.getJson(response);

            String p = (String) jsonObject.get(OP.P);
            String q = (String) jsonObject.get(OP.Q);
            String g = (String) jsonObject.get(OP.G);

            BigInteger P = new BigInteger(p);
            BigInteger Q = new BigInteger(q);
            BigInteger G = new BigInteger(g);

            LOG.info("Successfully received domain parameters!");

            return new DSAParameterSpec(P, Q, G);
        } catch (NullPointerException ex) {
            return null;
        }
    };

    private String genGetDomainParametersRequest() {
        JSONObject jsonObject = new JSONObject();

        jsonObject.put(OP.NAME, "client-"+this.uuid.toString());
        jsonObject.put(OP.METHOD, OP.GetDomainParameters);

        return jsonObject.toJSONString();
    }

    /**
     * Enroll client section.
     * */

    private IResponseProcessor processEnrollClientResponse = (response) -> {
        try {
            JSONObject jsonObject = JsonParser.getJson(response);
            return jsonObject.get(OP.Res).equals(OP.Success);

        } catch(NullPointerException ex) {
            return false;
        }
    };

    private String genEnrollClientRequest() {
        JSONObject jsonObject = new JSONObject();

        jsonObject.put(OP.NAME, "client-"+this.uuid.toString());
        jsonObject.put(OP.METHOD, OP.EnrollClient);

        return jsonObject.toJSONString();
    }

    private String genEnrollClientForStorageRequest() {
        JSONObject jsonObject = new JSONObject();

        jsonObject.put(OP.NAME, "client-"+this.uuid.toString());
        jsonObject.put(OP.METHOD, OP.EnrollClient);
        jsonObject.put(OP.Y, dsaPublicKey.toString());
        jsonObject.put(OP.PublicKeyRevision, publicKeyRevision);

        return jsonObject.toJSONString();
    }

    /**
     * Public key section.
     * */

    private IResponseProcessor processPublicKey = (response) -> {
        try {
            JSONObject jsonObject = JsonParser.getJson(response);

            if (jsonObject.containsKey(OP.Y)) {
                if (jsonObject.containsKey(OP.PublicKeyRevision)) {
                    publicKeyRevision = (long) jsonObject.get(OP.PublicKeyRevision);
                    LOG.info(String.format("Updating pub key revision to %d", publicKeyRevision));
                }

                return jsonObject.get(OP.Y);
            }

            LOG.severe(String.format("%s: %s", OP.Error, jsonObject.get(OP.Error)));
            return OP.Error;
        } catch (NullPointerException ex) {
            return OP.Error;
        }
    };

    private String genGetPublicKeyRequest() {
        JSONObject jsonObject = new JSONObject();

        jsonObject.put(OP.NAME, "client-"+this.uuid.toString());
        jsonObject.put(OP.METHOD, OP.GetPublicKey);

        return jsonObject.toJSONString();
    }

    /**
     * Key retrieval section.
     * */

    private IResponseProcessor processRetrieveKey = (response) -> {
        try {
            JSONObject jsonObject = JsonParser.getJson(response);

            if (jsonObject.containsKey(OP.V)) {
                return jsonObject.get(OP.V);
            }

            LOG.warning(String.format("%s: %s", OP.Error, jsonObject.get(OP.Error)));
            return OP.Error;
        } catch(NullPointerException ex) {
            return OP.Error;
        }
    };

    private String genRetrieveKeyRequest(BigInteger U) {
        JSONObject jsonObject = new JSONObject();

        jsonObject.put(OP.NAME, "client-"+this.uuid.toString());
        jsonObject.put(OP.METHOD, OP.RetrieveObjectKey);
        jsonObject.put(OP.U, U.toString());

        return jsonObject.toJSONString();
    }

    /**
     * Storing entries section.
     * */

    private IResponseProcessor processReadStorageEntryResponse = (response) -> {
        try {
            JSONObject jsonObject = JsonParser.getJson(response);

            if (jsonObject.get(OP.Res).equals(OP.Error)) {
                return null;
            }

            String objId = (String) jsonObject.get(OP.ObjId);
            String w = (String) jsonObject.get(OP.W);
            String encryptedObject = (String) jsonObject.get(OP.EncObj);
            return new ClientInformation().new ClientEntry(objId, w, encryptedObject);

        } catch (NullPointerException ex) {
            return null;
        }
    };

    private String genReadStorageEntryRequest(String objId) {
        JSONObject jsonObject = new JSONObject();

        jsonObject.put(OP.NAME, "client-"+this.uuid.toString());
        jsonObject.put(OP.METHOD, OP.ReadStorageEntry);
        jsonObject.put(OP.ObjId, objId);
        return jsonObject.toJSONString();
    }

    private IResponseProcessor processWriteStorageEntryResponse = (response) -> {
        try {
            JSONObject jsonObject = JsonParser.getJson(response);

            if (jsonObject.get(OP.Res).equals(OP.Error)) {
                String objId = (String) jsonObject.get(OP.ObjId);
                ivParameterSpecs.remove(objId);
                LOG.warning(String.format("Failed writing to storage. Removed '%s' from the list.", objId));

                long revision = (long) jsonObject.get(OP.PublicKeyRevision);
                LOG.info(String.format("Storage revision vs client revision: '%d' vs '%d'", revision, publicKeyRevision));
                if (revision > publicKeyRevision) {
                    LOG.warning("Your public key is out of date.\n".
                            concat("Please, update your public key, otherwise you won't be able to read from storage"));
                }

                return null;
            }
            return jsonObject.get(OP.ObjId);

        } catch (NullPointerException ex) {
            return null;
        }
    };

    private String genWriteStorageEntryRequest(String obj) throws InvalidKeyException, InvalidParameterException {
        String objId = UUID.randomUUID().toString();
        LOG.info(String.format("Storing object '%s': '%s'", objId, obj));

        BigInteger r = genEncryptionKey();
        if (!r.min(dsaParameterSpec.getQ()).equals(r)) {
            throw new InvalidKeyException("Error generating the object-specific encryption key");
        }
        LOG.info("Object-specific encryption key was created successfully!");

        IvParameterSpec ivParameterSpec = genInitializationVector();
        ivParameterSpecs.put(objId, ivParameterSpec);

        BigInteger w = dsaParameterSpec.getG().modPow(r, dsaParameterSpec.getP());
        String encryptedObject = encryptObject(obj, r, ivParameterSpec);
        if (encryptedObject == null) {
            throw new InvalidParameterException("Failed to encrypt the object");
        }
        LOG.info(String.format("The object was encrypted successfully: '%s'", encryptedObject));

        JSONObject jsonObject = new JSONObject();

        jsonObject.put(OP.NAME, "client-"+this.uuid.toString());
        jsonObject.put(OP.METHOD, OP.WriteStorageEntry);
        jsonObject.put(OP.ObjId, objId);
        jsonObject.put(OP.W, w.toString());
        jsonObject.put(OP.EncObj, encryptedObject);
        jsonObject.put(OP.PublicKeyRevision, publicKeyRevision);

        return jsonObject.toJSONString();
    }

    private String encryptObject(String obj, BigInteger encryptionKey, IvParameterSpec ivParameterSpec) {
        try {
            BigInteger encKey = dsaPublicKey.modPow(encryptionKey, dsaParameterSpec.getP());
            SecretKeySpec secretKeySpec = prepareSecretKey(encKey);

            Cipher cipher = Cipher.getInstance(SYMMETRIC_ENCRYPTION_DETAILS);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            return Base64.getEncoder().encodeToString(cipher.doFinal(obj.getBytes()));

        } catch (BadPaddingException |
                IllegalBlockSizeException |
                InvalidAlgorithmParameterException |
                InvalidKeyException |
                NoSuchAlgorithmException |
                NoSuchPaddingException ex) {
            LOG.severe(String.format("Error encrypting an object: %s", ex.getMessage()));
            return null;
        }
    }

    private String decryptWithKey(String encryptedObject, BigInteger encKey, IvParameterSpec ivParameterSpec) {
        String decryptedObject = decryptObject(encryptedObject, encKey, ivParameterSpec);
        if (decryptedObject.equals(OP.Error)) {
            LOG.info("The object was not decrypted successfully!");
            return null;
        }

        return decryptedObject;
    }

    private String decryptObject(String encryptedObject, BigInteger encKey, IvParameterSpec ivParameterSpec) {
        try {
            SecretKeySpec secretKeySpec = prepareSecretKey(encKey);

            Cipher cipher = Cipher.getInstance(SYMMETRIC_ENCRYPTION_DETAILS);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
            return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedObject)));

        } catch (BadPaddingException |
                IllegalBlockSizeException |
                InvalidAlgorithmParameterException |
                InvalidKeyException |
                NoSuchAlgorithmException |
                NoSuchPaddingException ex) {
            LOG.severe(String.format("Error decrypting an object: %s", ex.getMessage()));
            return OP.Error;
        }
    }

    private SecretKeySpec prepareSecretKey(BigInteger encKey) throws NoSuchAlgorithmException {
        byte[] key = encKey.toByteArray();
        MessageDigest sha = MessageDigest.getInstance(HASH_ALGO);

        key = sha.digest(key);
        key = Arrays.copyOf(key, HASH_KEY_LENGTH);
        return new SecretKeySpec(key, SYMMETRIC_ENCRYPTION_ALGO);
    }

    private BigInteger genEncryptionKey() {
        int qBitSize = dsaParameterSpec.getQ().bitCount();
        Random rnd = new Random();
        int bitSize = rnd.nextInt(qBitSize);
        while(bitSize < qBitSize / 2) { bitSize = rnd.nextInt(qBitSize); }

        return BigInteger.probablePrime(bitSize, new Random());
    }

    private IvParameterSpec genInitializationVector() {
        String rndStr = genRandomString(16);
        return new IvParameterSpec(rndStr.getBytes());
    }

    private String genRandomString(int len) {
        int left = 48; // 0
        int right = 123; // next after z

        Random r = new Random();
        return r.ints(left, right)
                .filter(i -> (i <= 57) || (i >= 65 && i <= 90) || (i >= 97))
                .limit(len)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();
    }
}
