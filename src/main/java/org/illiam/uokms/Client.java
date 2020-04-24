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

    private static Logger LOG = Logger.getLogger(Client.class.getName());

    /**
     * Communication constants.
     */
    private static int kmsPort = 9809;
    private static int stsPort = 9708;
    private static String kmsHost = "localhost";
    private static String stsHost = "localhost";

    /**
     * Crypto constants.
     * */
    private static final int SHA_KEY_LENGTH = 16;
    private static final String SYMMETRIC_ENCRYPTION_DETAILS = "AES/CBC/PKCS5Padding";
    private static final String SYMMETRIC_ENCRYPTION_ALGO = "AES";
    private static final String HASH_ALGO = "SHA-1";

    /**
     * Client identification and communication fields.
     * */
    private UUID uuid;
    //private Socket kmsSocket;

    /**
     * Crypto fields.
     * */
    private DSAParameterSpec dsaParameterSpec;
    private BigInteger dsaPublicKey;
    private boolean enrollmentStatus;

    private HashMap<UUID, BigInteger> encryptionKeys;
    private HashMap<UUID, IvParameterSpec> ivParameterSpecs;

    private String MSG = "is there anybody out here?";

    public static void main(String[] args) {
        parseArgs(args);

        Client client = new Client();
        client.runKms(kmsHost, kmsPort);

        client.storeMessage(client.MSG);
        UUID objId = (UUID) client.ivParameterSpecs.keySet().toArray()[0];
        client.getMessage(objId.toString());
    }

    private Client() {
        uuid = UUID.randomUUID();
        encryptionKeys = new HashMap<>();
        ivParameterSpecs = new HashMap<>();
        LOG.info(String.format("Created a client with an id: %s", uuid.toString()));
    }

    private static void parseArgs(String[] args) {
        if (args.length > 0) {
            kmsPort = Integer.parseInt(args[0]);
            LOG.info(String.format("Connecting to KMS on port %d", kmsPort));
        }

        if (args.length > 1) {
            stsPort = Integer.parseInt(args[1]);
            LOG.info(String.format("Connection to STS on port %d", stsPort));
        }
    }

    private void runKms(String kmsHost, int kmsPort) {
        try {
            communicate(kmsHost, kmsPort, genGetDomainParametersRequest(), processDomainParameters);
            LOG.info("Domain parameters were retrieved successfully!");

            communicate(kmsHost, kmsPort, genEnrollClientRequest(), processEnrollClientResponse);
            LOG.info(String.format("Success enrolling? -> %b", enrollmentStatus));

            if (!enrollmentStatus) {
                LOG.severe("Enrollment failed. Aborting...");
                System.exit(1);
            }

            communicate(kmsHost, kmsPort, genGetPublicKeyRequest(), processPublicKey);
            LOG.info("Public key was retrieved successfully!");

        } catch (IOException | ParseException ex) {
            LOG.severe(String.format("Error running client: %s", ex.getMessage()));
            ex.printStackTrace();
            System.exit(1);
        }
    }

    private void storeMessage(String msg) {
        try {
            LOG.info(String.format("Storing message: '%s'", msg));
            communicate(stsHost, stsPort, genWriteStorageEntryRequest(msg), processWriteStorageEntryResponse);

            LOG.info("Sleeping for 3 seconds");
            TimeUnit.SECONDS.sleep(3);

        } catch (IOException | ParseException | InvalidKeyException ex) {
            LOG.severe(String.format("Error storing a message: %s", ex.getMessage()));
            ex.printStackTrace();
            System.exit(1);
        } catch (InterruptedException ignore) {}
    }

    private void getMessage(String objId) {
        try {
            LOG.info(String.format("Getting message: '%s'", objId));
            communicate(stsHost, stsPort, genReadStorageEntryRequest(objId), processReadStorageEntryResponse);

            LOG.info("Sleeping for 3 seconds");
            TimeUnit.SECONDS.sleep(3);

        } catch (IOException | ParseException ex) {
            LOG.severe(String.format("Error storing a message: %s", ex.getMessage()));
            System.exit(1);
        } catch (InterruptedException ignore) {}
    }

    private void communicate(String host, int port, String request, IResponseProcessor processor)
            throws IOException, ParseException {
        Socket socket = new Socket(host, port);

        Communicator.SendMessage(socket, request);
        String response = Communicator.ReceiveMessage(socket);
        processor.ProcessResponse(response);

        socket.close();
    }

    /**
     * Domain parameters section.
     * */

    private IResponseProcessor processDomainParameters = (response) -> {
        JSONObject jsonObject = JsonParser.getJson(response);

        String p = (String) jsonObject.get("P");
        String q = (String) jsonObject.get("Q");
        String g = (String) jsonObject.get("G");

        BigInteger P = new BigInteger(p);
        BigInteger Q = new BigInteger(q);
        BigInteger G = new BigInteger(g);

        dsaParameterSpec = new DSAParameterSpec(P, Q, G);

        LOG.info("Successfully received domain parameters!");
        LOG.info(String.format("Value of P:\n%s\n", dsaParameterSpec.getP()));
        LOG.info(String.format("Value of Q:\n%s\n", dsaParameterSpec.getQ()));
        LOG.info(String.format("Value of G:\n%s\n", dsaParameterSpec.getG()));
    };

    private String genGetDomainParametersRequest() {
        JSONObject jsonObject = new JSONObject();

        jsonObject.put("name", "client-"+this.uuid.toString());
        jsonObject.put("method", "GetDomainParameters");

        return jsonObject.toJSONString();
    }

    /**
     * Enroll client section.
     * */

    private IResponseProcessor processEnrollClientResponse = (response) -> {
        JSONObject jsonObject = JsonParser.getJson(response);

        enrollmentStatus = (boolean) jsonObject.get("res");
        String comment = (String) jsonObject.get("comment");

        LOG.info("Successfully received EnrollClient response!");
        LOG.info(comment);
    };

    private String genEnrollClientRequest() {
        JSONObject jsonObject = new JSONObject();

        jsonObject.put("name", "client-"+this.uuid.toString());
        jsonObject.put("method", "EnrollClient");

        return jsonObject.toJSONString();
    }

    /**
     * Public key section.
     * */

    private IResponseProcessor processPublicKey = (response) -> {
        JSONObject jsonObject = JsonParser.getJson(response);

        String y = (String) jsonObject.get("Y");
        dsaPublicKey = new BigInteger(y);

        LOG.info(String.format("Successfully received a public key:\n%s", dsaPublicKey.toString()));
    };

    private String genGetPublicKeyRequest() {
        JSONObject jsonObject = new JSONObject();

        jsonObject.put("name", "client-"+this.uuid.toString());
        jsonObject.put("method", "GetPublicKey");

        return jsonObject.toJSONString();
    }

    /**
     * Storing entries section.
     * */

    private IResponseProcessor processReadStorageEntryResponse = (response) -> {
        JSONObject jsonObject = JsonParser.getJson(response);

        String objId = (String) jsonObject.get("objId");
        String w = (String) jsonObject.get("W");
        String encryptedMessage = (String) jsonObject.get("encMessage");

        LOG.info("Successfully received a response from storage!");
        LOG.info(String.format("Object ID:\n%s", objId));
        LOG.info(String.format("W:\n%s", w));
        LOG.info(String.format("Encrypted message:\n%s", encryptedMessage));
    };

    private String genReadStorageEntryRequest(String objId) {
        JSONObject jsonObject = new JSONObject();

        jsonObject.put("name", "client-"+this.uuid.toString());
        jsonObject.put("method", "ReadStorageEntry");
        jsonObject.put("objId", objId);
        return jsonObject.toJSONString();
    }

    private IResponseProcessor processWriteStorageEntryResponse = (response) -> {
        JSONObject jsonObject = JsonParser.getJson(response);

        String msg = (String) jsonObject.get("comment");

        LOG.info(String.format("Successfully received a response from storage: '%s'", msg));
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

        /*String decryptedMessage = decryptMessage(encryptedMessage, r, ivParameterSpec);
        LOG.info("The message was decrypted successfully!");
        LOG.info(String.format("Decrypted message:\n%s", decryptedMessage));
        if (!decryptedMessage.equals(msg)) {
            LOG.warning(String.format(
                "Received different decrypted message. Expected: '%s', got '%s'.", msg, decryptedMessage));
        } else {
            LOG.info("The decryption was correct!");
        }*/

        JSONObject jsonObject = new JSONObject();

        jsonObject.put("name", "client-"+this.uuid.toString());
        jsonObject.put("method", "WriteStorageEntry");
        jsonObject.put("objId", messageId.toString());
        jsonObject.put("W", w.toString());
        jsonObject.put("encMessage", encryptedMessage);

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

    private String decryptMessage(String encryptedMessage, BigInteger encryptionKey, IvParameterSpec ivParameterSpec) {
        String decryptedMessage = null;

        try {
            BigInteger encKey = dsaPublicKey.modPow(encryptionKey, dsaParameterSpec.getP());
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
            System.exit(1);
        }

        return decryptedMessage;
    }

    private SecretKeySpec prepareSecretKey(BigInteger encKey) throws NoSuchAlgorithmException {
        byte[] key = encKey.toByteArray();
        MessageDigest sha = MessageDigest.getInstance(HASH_ALGO);

        key = sha.digest(key);
        key = Arrays.copyOf(key, SHA_KEY_LENGTH);
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
