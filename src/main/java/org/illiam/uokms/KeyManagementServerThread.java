package main.java.org.illiam.uokms;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.interfaces.DSAPublicKey;
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
        String response = OP.Error;

        try {
            JSONParser jsonParser = new JSONParser();
            JSONObject jsonObject = (JSONObject) jsonParser.parse(request);

            response = executeRequest(jsonObject);

        } catch (ParseException ex) {
            KeyManager.Log(Level.SEVERE, ex.getMessage());
            ex.printStackTrace();
        }

        return response;
    }

    private String executeRequest(JSONObject request) {
        String name = (String) request.get(OP.NAME);
        String method = (String) request.get(OP.METHOD);
        KeyManager.Log(Level.INFO, String.format("Received request from '%s': '%s'", name, method));

        JSONObject jsonObject = new JSONObject();

        switch (method) {
            case OP.GetDomainParameters:
                DSAParameterSpec dsaParameterSpec = (DSAParameterSpec) KeyManager.GetDomainParameters();

                jsonObject.put(OP.P, dsaParameterSpec.getP().toString());
                jsonObject.put(OP.Q, dsaParameterSpec.getQ().toString());
                jsonObject.put(OP.G, dsaParameterSpec.getG().toString());
                jsonObject.put(OP.STATUS, OP.StatusOk);
                break;

            case OP.EnrollClient:
                boolean res = KeyManager.EnrollClient(name);
                String comment = res ? String.format("Client '%s' was enrolled successfully", name) :
                        String.format("Failed to enroll client '%s'", name);

                jsonObject.put(OP.Res, res);
                jsonObject.put(OP.Comment, comment);
                jsonObject.put(OP.STATUS, OP.StatusOk);
                break;

            case OP.GetPublicKey:
                DSAPublicKey pubkey = (DSAPublicKey) KeyManager.GetClientPublicKey(name);
                if (pubkey != null) {
                    jsonObject.put(OP.Y, pubkey.getY().toString());
                } else {
                    jsonObject.put(OP.Error, "The key was not retrieved. Perhaps, it's being updated.");
                }
                jsonObject.put(OP.STATUS, OP.StatusOk);
                break;

            case OP.RetrieveObjectKey:
                BigInteger U = new BigInteger((String) request.get(OP.U));
                BigInteger V = KeyManager.RetrieveClientKey(name, U);

                if (V != null) {
                    jsonObject.put(OP.V, V.toString());
                } else {
                    jsonObject.put(OP.Error, "The key was not retrieved. Perhaps, it's being updated.");
                }
                jsonObject.put(OP.STATUS, OP.StatusOk);
                break;

            default:
                jsonObject.put(OP.Error, OP.InvalidRequestMethod);
                jsonObject.put(OP.STATUS, OP.StatusNotFound);
                break;
        }

        return jsonObject.toJSONString();
    }
}
