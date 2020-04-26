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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.DSAParameterSpec;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

public class Client {

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
    private boolean enrollmentStatus;

    private HashMap<UUID, IvParameterSpec> ivParameterSpecs;

    private String MSG = "is there anybody out here?";

    public static void main(String[] args) {
        parseArgs(args);

        Client client = createClient();
        client.runKms();

        client.storeMessage(client.MSG);
        UUID objId = (UUID) client.ivParameterSpecs.keySet().toArray()[0];

        ClientInformation.ClientEntry entry = client.getMessage(objId.toString());

        BigInteger encKey = client.retrieveKey(entry);
        client.decryptWithKey(entry.encryptedMessage, encKey, client.ivParameterSpecs.get(objId));

        LOG.info("Sleeping for 1 minute...");
        try {TimeUnit.MINUTES.sleep(1);} catch (InterruptedException ignore) {}

        ClientInformation.ClientEntry newEntry = client.getMessage(objId.toString());

        BigInteger newEncKey = client.retrieveKey(newEntry);
        client.decryptWithKey(newEntry.encryptedMessage, newEncKey, client.ivParameterSpecs.get(objId));
    }

    private Client(String kmsHost, int kmsPort,
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

        uuid = UUID.randomUUID();
        ivParameterSpecs = new HashMap<>();

        LOG.info(String.format("Created a client with an id: %s", uuid.toString()));
    }

    private static Client createClient() {
        JSONObject jsonObject = ConfigLoader.LoadConfig(configFile);

        String kmsHost = (String) jsonObject.get(kmsHostName);
        long kmsPort = (long) jsonObject.get(kmsPortName);
        String stsHost = (String) jsonObject.get(stsHostName);
        long stsPort = (long) jsonObject.get(stsPortName);

        String symEncAlgo = (String) jsonObject.get(symAlgoName);
        String symEncAlgoDetails = (String) jsonObject.get(symAlgoDetailsName);
        String hashAlgo = (String) jsonObject.get(hashAlgoName);
        long hashAlgoKeyLen = (long) jsonObject.get(hashKeyLenName);

        Client client = new Client(
                kmsHost, (int) kmsPort,
                stsHost, (int) stsPort,
                symEncAlgo, symEncAlgoDetails,
                hashAlgo, (int) hashAlgoKeyLen);
        return client;
    }

    private static void parseArgs(String[] args) {

    }

    private void runKms() {
        try {
            dsaParameterSpec = (DSAParameterSpec) communicate(
                    kmsHost, kmsPort, genGetDomainParametersRequest(), processDomainParameters);
            LOG.info("Domain parameters were retrieved successfully!");

            enrollmentStatus = (boolean) communicate(
                    kmsHost, kmsPort, genEnrollClientRequest(), processEnrollClientResponse);
            LOG.info(String.format("Success enrolling? -> %b", enrollmentStatus));

            if (!enrollmentStatus) {
                LOG.severe("Enrollment failed. Aborting...");
                System.exit(1);
            }

            String pubKeyResult = (String) communicate(kmsHost, kmsPort, genGetPublicKeyRequest(), processPublicKey);
            if (pubKeyResult.equals("error")) {
                LOG.info("Public key was not retrieved!");
                return;
            }

            dsaPublicKey = new BigInteger(pubKeyResult);
            LOG.info("Public key was retrieved successfully!");

        } catch (IOException | ParseException ex) {
            LOG.severe(String.format("Error running client: %s", ex.getMessage()));
            ex.printStackTrace();
            System.exit(1);
        }
    }

    private BigInteger retrieveKey(ClientInformation.ClientEntry entry) {
        BigInteger key = null;

        try {
            BigInteger rr = genEncryptionKey();
            BigInteger U = new BigInteger(entry.w).modPow(rr, dsaParameterSpec.getP());

            String v = (String) communicate(kmsHost, kmsPort, genRetrieveKeyRequest(U), processRetrieveKey);
            while(v.equals(OP.Error)) {
                LOG.warning("Sleeping because could not retrieve a key");
                TimeUnit.MILLISECONDS.sleep(100);
                v = (String) communicate(kmsHost, kmsPort, genRetrieveKeyRequest(U), processRetrieveKey);
            }
            BigInteger V = new BigInteger(v);
            LOG.info("The key was retrieved successfully!");

            BigInteger rrInverse = rr.modInverse(dsaParameterSpec.getQ());
            key = V.modPow(rrInverse, dsaParameterSpec.getP());

        } catch (IOException | ParseException ex) {
            LOG.severe(String.format("Error running client: %s", ex.getMessage()));
            ex.printStackTrace();
            System.exit(1);
        } catch (InterruptedException ignore) {}

        return key;
    }

    private void storeMessage(String msg) {
        try {
            LOG.info(String.format("Storing message: '%s'", msg));
            communicate(stsHost, stsPort, genWriteStorageEntryRequest(msg), processWriteStorageEntryResponse);
        } catch (IOException | ParseException | InvalidKeyException ex) {
            LOG.severe(String.format("Error storing a message: %s", ex.getMessage()));
            ex.printStackTrace();
            System.exit(1);
        }
    }

    private ClientInformation.ClientEntry getMessage(String objId) {
        ClientInformation.ClientEntry entry = null;

        try {
            LOG.info(String.format("Getting message: '%s'", objId));
            entry = (ClientInformation.ClientEntry) communicate(
                            stsHost, stsPort, genReadStorageEntryRequest(objId), processReadStorageEntryResponse);
        } catch (IOException | ParseException ex) {
            LOG.severe(String.format("Error storing a message: %s", ex.getMessage()));
            System.exit(1);
        }

        return entry;
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
        JSONObject jsonObject = JsonParser.getJson(response);

        String p = (String) jsonObject.get(OP.P);
        String q = (String) jsonObject.get(OP.Q);
        String g = (String) jsonObject.get(OP.G);

        BigInteger P = new BigInteger(p);
        BigInteger Q = new BigInteger(q);
        BigInteger G = new BigInteger(g);

        LOG.info("Successfully received domain parameters!");

        return new DSAParameterSpec(P, Q, G);
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
        JSONObject jsonObject = JsonParser.getJson(response);

        String comment = (String) jsonObject.get(OP.Comment);
        LOG.info(comment);

        return (boolean) jsonObject.get(OP.Res);
    };

    private String genEnrollClientRequest() {
        JSONObject jsonObject = new JSONObject();

        jsonObject.put(OP.NAME, "client-"+this.uuid.toString());
        jsonObject.put(OP.METHOD, OP.EnrollClient);

        return jsonObject.toJSONString();
    }

    /**
     * Public key section.
     * */

    private IResponseProcessor processPublicKey = (response) -> {
        JSONObject jsonObject = JsonParser.getJson(response);

        if (jsonObject.containsKey(OP.Y)) {
            String y = (String) jsonObject.get(OP.Y);
            LOG.info(String.format("Successfully received a public key:\n%s", y));

            return y;
        }

        LOG.warning(String.format("%s: %s", OP.Error, jsonObject.get(OP.Error)));
        return OP.Error;
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
        JSONObject jsonObject = JsonParser.getJson(response);

        if (jsonObject.containsKey(OP.V)) {
            String v = (String) jsonObject.get(OP.V);
            LOG.info(String.format("Successfully retrieved a key:\n%s", v));

            return v;
        }

        LOG.warning(String.format("%s: %s", OP.Error, jsonObject.get(OP.Error)));
        return OP.Error;
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
        JSONObject jsonObject = JsonParser.getJson(response);

        String objId = (String) jsonObject.get(OP.ObjId);
        String w = (String) jsonObject.get(OP.W);
        String encryptedMessage = (String) jsonObject.get(OP.EncMsg);

        LOG.info("Successfully received a response from storage!");
        LOG.info(String.format("Object ID:\n%s", objId));
        LOG.info(String.format("Encrypted message:\n%s", encryptedMessage));

        return new ClientInformation().new ClientEntry(objId, w, encryptedMessage);
    };

    private String genReadStorageEntryRequest(String objId) {
        JSONObject jsonObject = new JSONObject();

        jsonObject.put(OP.NAME, "client-"+this.uuid.toString());
        jsonObject.put(OP.METHOD, OP.ReadStorageEntry);
        jsonObject.put(OP.ObjId, objId);
        return jsonObject.toJSONString();
    }

    private IResponseProcessor processWriteStorageEntryResponse = (response) -> {
        JSONObject jsonObject = JsonParser.getJson(response);

        String msg = (String) jsonObject.get(OP.Comment);
        LOG.info(String.format("Successfully received a response from storage: '%s'", msg));
        return msg;
    };

    private String genWriteStorageEntryRequest(String msg) throws InvalidKeyException {
        UUID messageId = UUID.randomUUID();
        BigInteger r = genEncryptionKey();

        if (r.min(dsaParameterSpec.getQ()).equals(r)) {
            LOG.info("Encryption key for a message was created successfully!");
        } else {
            LOG.severe(String.format("Error generating a key:\n%s", r.toString()));
            throw new InvalidKeyException();
        }

        IvParameterSpec ivParameterSpec = genInitializationVector();
        ivParameterSpecs.put(messageId, ivParameterSpec);

        BigInteger w = dsaParameterSpec.getG().modPow(r, dsaParameterSpec.getP());
        LOG.info(String.format("Encryption parameter:\n%s", w));

        String encryptedMessage = encryptMessage(msg, r, ivParameterSpec);
        LOG.info(String.format("The message was encrypted successfully:\n%s", encryptedMessage));

        JSONObject jsonObject = new JSONObject();

        jsonObject.put(OP.NAME, "client-"+this.uuid.toString());
        jsonObject.put(OP.METHOD, OP.WriteStorageEntry);
        jsonObject.put(OP.ObjId, messageId.toString());
        jsonObject.put(OP.W, w.toString());
        jsonObject.put(OP.EncMsg, encryptedMessage);

        return jsonObject.toJSONString();
    }

    private String encryptMessage(String msg, BigInteger encryptionKey, IvParameterSpec ivParameterSpec) {
        String encryptedMessage = null;

        try {
            BigInteger encKey = dsaPublicKey.modPow(encryptionKey, dsaParameterSpec.getP());
            SecretKeySpec secretKeySpec = prepareSecretKey(encKey);

            Cipher cipher = Cipher.getInstance(SYMMETRIC_ENCRYPTION_DETAILS);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            encryptedMessage = Base64.getEncoder().encodeToString(cipher.doFinal(msg.getBytes("UTF-8")));

        } catch (BadPaddingException |
                IllegalBlockSizeException |
                InvalidAlgorithmParameterException |
                InvalidKeyException |
                NoSuchAlgorithmException |
                NoSuchPaddingException |
                UnsupportedEncodingException ex) {
            LOG.severe(String.format("Error encrypting a message: %s", ex.getMessage()));
            System.exit(1);
        }

        return encryptedMessage;
    }

    private void decryptWithKey(String encryptedMessage, BigInteger encKey, IvParameterSpec ivParameterSpec) {
        String decryptedMessage = decryptMessage(encryptedMessage, encKey, ivParameterSpec);
        if (!decryptedMessage.equals(OP.Error)) {
            LOG.info("The message was decrypted successfully!");
        }
        LOG.info(String.format("Decrypted message:\n%s", decryptedMessage));
        if (!decryptedMessage.equals(MSG)) {
            LOG.warning(String.format(
                    "Received different decrypted message. Expected: '%s', got '%s'.", MSG, decryptedMessage));
            LOG.warning("This happens if the STS object is old, but the KMS public key is new");
            LOG.warning("This happens when such sequence occures: GetObj -> UpdKey -> GetKey.");
            LOG.warning("Please, safely discard the object data and retry the process");
        } else {
            LOG.info("The decryption was correct!");
        }
    }

    private String decryptMessage(String encryptedMessage, BigInteger encKey, IvParameterSpec ivParameterSpec) {
        String decryptedMessage = null;

        try {
            SecretKeySpec secretKeySpec = prepareSecretKey(encKey);

            Cipher cipher = Cipher.getInstance(SYMMETRIC_ENCRYPTION_DETAILS);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
            decryptedMessage = new String(cipher.doFinal(Base64.getDecoder().decode(encryptedMessage)));

        } catch (BadPaddingException |
                IllegalBlockSizeException |
                InvalidAlgorithmParameterException |
                InvalidKeyException |
                NoSuchAlgorithmException |
                NoSuchPaddingException ex) {
            LOG.severe(String.format("Error decrypting a message: %s", ex.getMessage()));
            return OP.Error;
        }

        return decryptedMessage;
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
        byte[] iv = new byte[16];
        Random rnd = new Random();
        rnd.nextBytes(iv);
        return new IvParameterSpec(iv);
    }
}
