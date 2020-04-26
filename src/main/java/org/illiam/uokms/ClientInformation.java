package main.java.org.illiam.uokms;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.logging.Level;

public class ClientInformation {

    public class ClientEntry {
        //private int publicKeyRevision;

        public final String objId;
        public String w;
        public final String encryptedObject;

        public ClientEntry(String objId, String w, String encryptedObject) {
            this.objId = objId;
            this.w = w;
            this.encryptedObject = encryptedObject;
            //this.publicKeyRevision = pubKeyRevision;
        }
    }

    private BigInteger currentPublicKey;
    private long currentPubKeyRevision;

    private HashMap<String, ClientEntry> entries;

    public ClientInformation() {
        entries = new HashMap<>();
    }

    public void SetCurrentPublicKey(BigInteger publicKey, long pubKeyRevision) {
        currentPublicKey = publicKey;
        currentPubKeyRevision = pubKeyRevision;
    }

    public BigInteger GetCurrentPublicKey() {
        return currentPublicKey;
    }

    public boolean AddEntry(String objId, String w, String encryptedObject) {
        /*if (currentPublicKey == null) {
            currentPublicKey = pubKey;
        }

        // The object was encrypted with an obsolete public key.
        // Don't store and return an error.
        if (!currentPublicKey.equals(pubKey)) {
            return false;
        }*/

        entries.put(objId, new ClientEntry(objId, w, encryptedObject));
        return true;
    }

    public ClientEntry GetEntry(String objId) {
        return entries.getOrDefault(objId, null);
    }

    public void SetDelta(BigInteger delta, BigInteger p) {
        for (ClientEntry entry : entries.values()) {
            Storage.Log(Level.INFO, String.format("Updating the key for obj: '%s'", entry.objId));

            BigInteger oldW = new BigInteger(entry.w);
            BigInteger newW = oldW.modPow(delta, p);
            entry.w = newW.toString();
        }

    }
}
