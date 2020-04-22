package main.java.org.illiam.uokms;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.io.*;
import java.net.Socket;
import java.security.spec.DSAParameterSpec;
import java.util.logging.Level;

public class KeyManagementServerThread extends Thread {

    private Socket socket;

    public KeyManagementServerThread(Socket socket) {
        this.socket = socket;
    }

    public void run() {
        try {
            Communicator c = new Communicator();

            String msg = c.ReceiveMessage(socket);
            String response = processRequest(msg);
            c.SendMessage(socket, response);

            socket.close();
        } catch (IOException ex) {
            KeyManager.Log(Level.SEVERE, ex.getMessage());
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
        JSONObject jsonObject = new JSONObject();

        switch (method) {
            case "GetDomainParameters":
                DSAParameterSpec dsaParameterSpec = (DSAParameterSpec) KeyManager.GetDomainParameters();

                jsonObject.put("P", dsaParameterSpec.getP().toString());
                jsonObject.put("Q", dsaParameterSpec.getQ().toString());
                jsonObject.put("G", dsaParameterSpec.getG().toString());
                jsonObject.put("status", "200");
                break;

            default:
                jsonObject.put("resp", "bad request method");
                jsonObject.put("status", "404");
                break;
        }

        return jsonObject.toJSONString();
    }
}
