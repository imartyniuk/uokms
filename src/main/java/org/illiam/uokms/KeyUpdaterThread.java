package main.java.org.illiam.uokms;

import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.time.LocalTime;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;

public class KeyUpdaterThread extends Thread {
    private final int RUN_PERIOD = 9;
    private final int UPDATE_PERIOD = 30;

    private final int stsPort = 9708;
    private final String stsHost = "localhost";

    public void run() {
        try {
            while (true) {
                KeyManager.Log(Level.INFO, String.format("Sleeping for %d seconds...", RUN_PERIOD));
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

            KeyPair newKeyPair = KeyManager.GenKeyPair();
            BigInteger delta = KeyManager.GenDelta(name, newKeyPair);
            KeyManager.Log(Level.INFO, String.format("Generated delta:\n%s", delta));

            KeyManager.SetUpdateState(name, true);

            boolean res = (boolean) communicate(
                    stsHost, stsPort, genUpdateKeyRequest(name, delta), processUpdateKeyResponse);

            if (res) {
                KeyManager.Log(Level.INFO, String.format("Storage key was updated successfully!"));
                KeyManager.UpdateClient(name, newKeyPair);
                KeyManager.Log(Level.INFO, String.format("The key for client '%s' was updated successfully!", name));
            } else {
                KeyManager.Log(Level.WARNING, String.format("The key for client '%s' was not updated!", name));
            }

            KeyManager.SetUpdateState(name, false);

        } catch(InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException |
                IOException | ParseException ex) {
            KeyManager.Log(Level.WARNING,
                    String.format("Error updating the key for client '%s': %s", name, ex.getMessage()));
            ex.printStackTrace();
        }
    }

    private IResponseProcessor processUpdateKeyResponse = (response) -> {
        JSONObject jsonObject = JsonParser.getJson(response);

        KeyManager.Log(Level.INFO, "Successfully received UpdateKey response!");

        return (boolean) jsonObject.get(OP.Res);
    };

    private String genUpdateKeyRequest(String name, BigInteger delta) {
        JSONObject jsonObject = new JSONObject();

        jsonObject.put(OP.NAME, name);
        jsonObject.put(OP.METHOD, OP.UpdateKey);
        jsonObject.put(OP.Delta, delta.toString());

        return jsonObject.toJSONString();
    }
}
