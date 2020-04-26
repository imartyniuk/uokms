package main.java.org.illiam.uokms;

import org.json.simple.JSONObject;

import java.math.BigInteger;
import java.security.spec.DSAParameterSpec;
import java.util.HashMap;
import java.util.UUID;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Storage {

    /**
     * Config section.
     * */
    private static final String configFile = "sts_config.json";
    private static final String portName = "port";
    private static final String kmsHostName = "kmsHost";
    private static final String kmsPortName = "kmsPort";

    /**
     * Logging section.
     * */
    private static Logger LOG = Logger.getLogger(Storage.class.getName());

    /**
     * Storage GUID.
     * */
    private static UUID uuid = UUID.randomUUID();

    /**
     * Clients' data.
     * */
    private static ReadWriteLock rwLock;
    private static HashMap<String, ClientInformation> clientData;

    /**
     * Domain parameters.
     * */
    private static DSAParameterSpec dsaParameterSpec;

    public static void main(String[] args) {
        initializeStorage();

        startStorageServer();
    }

    private static void initializeStorage() {
        rwLock = new ReentrantReadWriteLock();
        clientData = new HashMap<>();
    }

    private static void startStorageServer() {
        JSONObject jsonObject = ConfigLoader.LoadConfig(configFile);

        long port = (long) jsonObject.get(portName);
        String kmsHost = (String) jsonObject.get(kmsHostName);
        long kmsPort = (long) jsonObject.get(kmsPortName);

        StorageServer storageServer = new StorageServer((int)port, kmsHost, (int)kmsPort);
        storageServer.Start();
    }

    public static boolean EnrollClient(String client, BigInteger pubKey, long pubKeyRevision) {
        Lock writeLock = rwLock.writeLock();
        try {
            writeLock.lock();

            // Client is already enrolled.
            if (clientData.containsKey(client)) {
                return false;
            }

            clientData.put(client, new ClientInformation());
            clientData.get(client).SetCurrentPublicKey(pubKey, pubKeyRevision);

            return true;

        } finally {
            writeLock.unlock();
        }
    }

    public static boolean WriteStorageEntry(String client, String objId, String w, String encryptedObject) {
        Lock writeLock = rwLock.writeLock();
        try {
            writeLock.lock();
            if (!clientData.containsKey(client)) {
                return false;
            }
            clientData.get(client).AddEntry(objId, w, encryptedObject);

            return true;

        } finally {
            writeLock.unlock();
        }
    }

    public static ClientInformation.ClientEntry ReadStorageEntry(String client, String objId) {
        Lock readLock = rwLock.readLock();
        try {
            readLock.lock();
            LOG.info(String.format("ReadStorageEntry: '%s'", objId));
            if (!clientData.containsKey(client)) {
                return null;
            }

            return clientData.get(client).GetEntry(objId);

        } finally {
            readLock.unlock();
        }
    }

    public static boolean UpdateKey(String client, BigInteger delta) {
        Lock writeLock = rwLock.writeLock();
        try {
            writeLock.lock();
            LOG.info(String.format("UpdateKey: '%s'", client));
            if (!clientData.containsKey(client)) {
                clientData.put(client, new ClientInformation());
            }

            clientData.get(client).SetDelta(delta, dsaParameterSpec.getP());
            return true;

        } finally {
            writeLock.unlock();
        }
    }

    public static IResponseProcessor processDomainParameters = (response) -> {
        JSONObject jsonObject = JsonParser.getJson(response);

        String p = (String) jsonObject.get(OP.P);
        String q = (String) jsonObject.get(OP.Q);
        String g = (String) jsonObject.get(OP.G);

        BigInteger P = new BigInteger(p);
        BigInteger Q = new BigInteger(q);
        BigInteger G = new BigInteger(g);
        dsaParameterSpec = new DSAParameterSpec(P, Q, G);

        LOG.info("Successfully received domain parameters!");

        return dsaParameterSpec;
    };

    public static String genGetDomainParametersRequest() {
        JSONObject jsonObject = new JSONObject();

        jsonObject.put(OP.NAME, "storage-"+uuid.toString());
        jsonObject.put(OP.METHOD, OP.GetDomainParameters);

        return jsonObject.toJSONString();
    }

    public static void Log(Level level, String err) {
        LOG.log(level, err);
    }
}
