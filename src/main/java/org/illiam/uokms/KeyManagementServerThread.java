package org.illiam.uokms;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.io.*;
import java.net.Socket;
import java.security.spec.DSAParameterSpec;
import java.util.logging.Level;

public class KeyManagementServerThread extends Thread {

    private static final String packetEnd = "<FIN>";

    private Socket socket;

    public KeyManagementServerThread(Socket socket) {
        this.socket = socket;
    }

    public void run() {
        try {

            String msg = receiveMessage(socket);
            String response = processRequest(msg);
            sendMessage(socket, response);

            socket.close();
        } catch (IOException ex) {
            KeyManager.Log(Level.SEVERE, ex.getMessage());
            ex.printStackTrace();
        }
    }

    private String receiveMessage(Socket socket) throws IOException {
        InputStream is = socket.getInputStream();
        BufferedReader br = new BufferedReader(new InputStreamReader(is));

        StringBuilder sb = new StringBuilder();
        String text;
        do {
            text = br.readLine();
            sb.append(text);
        } while (!text.equals(packetEnd));

        String msg = sb.toString().replace(packetEnd, "");
        KeyManager.Log(Level.INFO, String.format("Received message:\n%s", msg));

        return msg;
    }

    private void sendMessage(Socket socket, String msg) throws IOException {
        OutputStream os = socket.getOutputStream();
        PrintWriter pw = new PrintWriter(os, true);

        pw.println(msg);
        pw.println(packetEnd);
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
