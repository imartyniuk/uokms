package main.java.org.illiam.uokms;

import java.util.HashMap;

public class ClientInformation {

    public class ClientEntry {
        public final String objId;
        public final String w;
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

}
