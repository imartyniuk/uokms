package main.java.org.illiam.uokms;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

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

    private static Logger LOG = Logger.getLogger(Storage.class.getName());
    private static UUID uuid = UUID.randomUUID();

    private static ReadWriteLock rwLock;
    private static DSAParameterSpec dsaParameterSpec;

    private static HashMap<String, ClientInformation> clientData;

    public static void main(String[] args) {
        initializeStorage();

        StorageServer storageServer = new StorageServer();
        storageServer.Start();
    }

    private static void initializeStorage() {
        rwLock = new ReentrantReadWriteLock();
        clientData = new HashMap<>();
    }

    public static void WriteStorageEntry(String client, String objId, String w, String encryptedMessage) {
        Lock writeLock = rwLock.writeLock();
        try {
            writeLock.lock();
            if (!clientData.containsKey(client)) {
                clientData.put(client, new ClientInformation());
            }
            clientData.get(client).AddEntry(objId, w, encryptedMessage);

        } finally {
            writeLock.unlock();
        }
    }

    public static ClientInformation.ClientEntry ReadStorageEntry(String client, String objId) {
        Lock readLock = rwLock.readLock();
        try {
            readLock.lock();
            LOG.info(String.format("ReadStorageEntry: '%s'", client));
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

        return dsaParameterSpec;
    };

    public static String genGetDomainParametersRequest() {
        JSONObject jsonObject = new JSONObject();

        jsonObject.put("name", "storage-"+uuid.toString());
        jsonObject.put("method", "GetDomainParameters");

        return jsonObject.toJSONString();
    }

    public static void Log(Level level, String err) {
        LOG.log(level, err);
    }
}
