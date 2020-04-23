package main.java.org.illiam.uokms;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.math.BigInteger;
import java.security.spec.DSAParameterSpec;
import java.util.UUID;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Storage {

    private static Logger LOG = Logger.getLogger(Storage.class.getName());
    private static UUID uuid = UUID.randomUUID();

    private static ReadWriteLock rwLock;
    private static DSAParameterSpec dsaParameterSpec;

    public static void main(String[] args) {
        StorageServer storageServer = new StorageServer();
        storageServer.Start();
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
