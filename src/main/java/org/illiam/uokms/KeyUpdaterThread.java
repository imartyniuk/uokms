package main.java.org.illiam.uokms;

import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.time.LocalTime;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;

public class KeyUpdaterThread extends Thread {
    private final int RUN_PERIOD;
    private final int UPDATE_PERIOD;

    private final String stsHost;
    private final int stsPort;

    public KeyUpdaterThread(int runPeriod, int updPeriod, String stsHost, int stsPort) {
        RUN_PERIOD = runPeriod;
        UPDATE_PERIOD = updPeriod;
        this.stsHost = stsHost;
        this.stsPort = stsPort;
    }

    public void run() {
        try {
            KeyManager.Log(Level.INFO, "KeyUpdater thread has started");

            while (true) {
                TimeUnit.SECONDS.sleep(RUN_PERIOD);

                updateClientKeys();
            }

        } catch (InterruptedException ignore) {}
    }

    private void updateClientKeys() {
        LocalTime currentTime = LocalTime.now();

        List<String> clientsToUpd = new ArrayList<>();

        Object[] clients = KeyManager.GetClients();
        for (Object c : clients) {
            String client = (String) c;
            LocalTime lastUpd = KeyManager.GetLastUpdated(client);
            if (lastUpd.plusSeconds(UPDATE_PERIOD).isBefore(currentTime)) {
                clientsToUpd.add(client);
            }
        }

        for (String c: clientsToUpd) {
            updateClientKey(c);
        }
    }

    private Object communicate(String stsHost, int stsPort, String request, IResponseProcessor processor)
            throws IOException, ParseException {
        Socket stsSocket = new Socket(stsHost, stsPort);

        Communicator.SendMessage(stsSocket, request);
        String response = Communicator.ReceiveMessage(stsSocket);

        stsSocket.close();

        return processor.ProcessResponse(response);
    }

    private void updateClientKey(String name) {
        try {
            KeyManager.Log(Level.INFO, String.format("Updating the key for client '%s'", name));

            long startUpd = System.nanoTime();

            KeyPair newKeyPair = KeyManager.GenKeyPair();
            BigInteger delta = KeyManager.GenDelta(name, newKeyPair);

            KeyManager.SetUpdateState(name, true);

            boolean res = (boolean) communicate(
                    stsHost, stsPort, genUpdateKeyRequest(name, delta), processUpdateKeyResponse);

            if (res) {
                KeyManager.UpdateClient(name, newKeyPair);
                KeyManager.Log(Level.INFO, String.format("The key for client '%s' was updated successfully!", name));
            } else {
                KeyManager.Log(Level.WARNING, String.format("The key for client '%s' was not updated!", name));
            }

            KeyManager.SetUpdateState(name, false);

            long endUpd = System.nanoTime();
            KeyManager.LogTime(Double.toString( (endUpd - startUpd) / 1000000.0), "upd", true);


        } catch(InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException |
                IOException | ParseException ex) {
            KeyManager.Log(Level.WARNING,
                    String.format("Error updating the key for client '%s': %s", name, ex.getMessage()));
            ex.printStackTrace();
        }
    }

    private IResponseProcessor processUpdateKeyResponse = (response) -> {
        JSONObject jsonObject = JsonParser.getJson(response);
        return (boolean) jsonObject.get(OP.Res);
    };

    private String genUpdateKeyRequest(String name, BigInteger delta) {
        JSONObject jsonObject = new JSONObject();

        jsonObject.put(OP.NAME, name);
        jsonObject.put(OP.METHOD, OP.UpdateKey);
        jsonObject.put(OP.Delta, delta.toString());
        jsonObject.put(OP.PublicKeyRevision, KeyManager.GetPublicKeyRevision(name) + 1);

        return jsonObject.toJSONString();
    }
}
