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

            String name = (String) jsonObject.get("name");
            String method = (String) jsonObject.get("method");

            KeyManager.Log(Level.INFO, String.format("Received request from %s", name));
            KeyManager.Log(Level.INFO, String.format("Requested method: %s", method));

            response = executeRequest(name, method);

        } catch (ParseException ex) {
            KeyManager.Log(Level.SEVERE, ex.getMessage());
            ex.printStackTrace();
        }

        return response;
    }

    private String executeRequest(String name, String method) {
        Storage.Log(Level.INFO, String.format("Received request: '%s'", method));

        JSONObject jsonObject = new JSONObject();
        jsonObject.put("message", "i am a storage lol");
        jsonObject.put("status", "200");
        return jsonObject.toJSONString();
    }
}
