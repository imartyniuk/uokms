package main.java.org.illiam.uokms;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.io.IOException;
import java.net.Socket;
import java.util.logging.Level;

public class StorageServerThread extends Thread {

    private Socket socket;

    public StorageServerThread(Socket socket) {
        this.socket = socket;
    }

    public void run() {
        try {
            String msg = Communicator.ReceiveMessage(socket);
            String response = processRequest(msg);
            Communicator.SendMessage(socket, response);

            socket.close();
        } catch (IOException ex) {
            Storage.Log(Level.SEVERE, ex.getMessage());
            ex.printStackTrace();
        }
    }

    private String processRequest(String request) {
        String response = "failure processing";

        try {
            JSONParser jsonParser = new JSONParser();
            JSONObject jsonObject = (JSONObject) jsonParser.parse(request);

            response = executeRequest(jsonObject);

        } catch (ParseException ex) {
            Storage.Log(Level.SEVERE, ex.getMessage());
            ex.printStackTrace();
        }

        return response;
    }

    private String executeRequest(JSONObject request) {
        String name = (String) request.get("name");
        String method = (String) request.get("method");
        String objId = (String) request.get("objId");

        Storage.Log(Level.INFO, String.format("Received request from '%s'", name));
        Storage.Log(Level.INFO, String.format("Requested method: '%s'", method));

        JSONObject jsonObject = new JSONObject();

        try {
            switch (method) {
                case "WriteStorageEntry":
                    String w = (String) request.get("W");
                    String encryptedMessage = (String) request.get("encMessage");

                    Storage.WriteStorageEntry(name, objId, w, encryptedMessage);

                    jsonObject.put("comment", "success");
                    jsonObject.put("status", "200");
                    break;

                case "ReadStorageEntry":
                    ClientInformation.ClientEntry entry = Storage.ReadStorageEntry(name, objId);
                    if (entry == null) {
                        jsonObject.put("comment", "failed");
                        jsonObject.put("status", "500");
                    } else {
                        jsonObject.put("objId", entry.objId);
                        jsonObject.put("W", entry.w);
                        jsonObject.put("encMessage", entry.encryptedMessage);
                        jsonObject.put("status", "200");
                    }
                    break;

                default:
                    jsonObject.put("resp", "Invalid request method");
                    jsonObject.put("status", "404");
            }
        } catch (Exception ex) {
            Storage.Log(Level.SEVERE, ex.getMessage());
            ex.printStackTrace();
        }

        return jsonObject.toJSONString();
    }
}
