package main.java.org.illiam.uokms;

import java.math.BigInteger;
import java.util.HashMap;

public class ClientInformation {

    public class ClientEntry {
        public final String objId;
        public String w;
        public final String encryptedMessage;

        public ClientEntry(String objId, String w, String encryptedMessage) {
            this.objId = objId;
            this.w = w;
            this.encryptedMessage = encryptedMessage;
        }
    }
    private HashMap<String, ClientEntry> entries;

    public ClientInformation() {
        entries = new HashMap<>();
    }

    public void AddEntry(String objId, String w, String encryptedMessage) {
        entries.put(objId, new ClientEntry(objId, w, encryptedMessage));
    }

    public ClientEntry GetEntry(String objId) {
        return entries.getOrDefault(objId, null);
    }

    public void SetDelta(BigInteger delta, BigInteger p) {
        for (ClientEntry entry : entries.values()) {
            BigInteger oldW = new BigInteger(entry.w);
            BigInteger newW = oldW.modPow(delta, p);
            entry.w = newW.toString();
        }

    }
}
