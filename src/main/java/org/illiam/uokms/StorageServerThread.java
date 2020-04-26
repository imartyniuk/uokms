package main.java.org.illiam.uokms;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.io.IOException;
import java.math.BigInteger;
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
        String response = OP.Error;

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
        String name = (String) request.get(OP.NAME);
        String method = (String) request.get(OP.METHOD);
        String objId = null;

        Storage.Log(Level.INFO, String.format("Received request from '%s': '%s'", name, method));

        JSONObject jsonObject = new JSONObject();

        try {
            switch (method) {
                case OP.EnrollClient:
                    String y = (String) request.get(OP.Y);
                    long revision = (long) request.get(OP.PublicKeyRevision);

                    if (Storage.EnrollClient(name, new BigInteger(y), revision)) {
                        jsonObject.put(OP.Res, OP.Success);
                        jsonObject.put(OP.STATUS, OP.StatusOk);
                    } else {
                        jsonObject.put(OP.Res, OP.Error);
                        jsonObject.put(OP.STATUS, OP.StatusInternalError);
                    }
                    break;

                case OP.WriteStorageEntry:
                    objId = (String) request.get(OP.ObjId);
                    String w = (String) request.get(OP.W);
                    String encryptedObject = (String) request.get(OP.EncObj);

                    jsonObject.put(OP.ObjId, objId);
                    if (Storage.WriteStorageEntry(name, objId, w, encryptedObject)) {
                        jsonObject.put(OP.Res, OP.Success);
                        jsonObject.put(OP.STATUS, OP.StatusOk);
                    } else {
                        jsonObject.put(OP.Res, OP.Error);
                        jsonObject.put(OP.STATUS, OP.StatusInternalError);
                    }

                    break;

                case OP.ReadStorageEntry:
                    objId = (String) request.get(OP.ObjId);
                    ClientInformation.ClientEntry entry = Storage.ReadStorageEntry(name, objId);
                    if (entry == null) {
                        jsonObject.put(OP.Res, OP.Error);
                        jsonObject.put(OP.STATUS, OP.StatusInternalError);
                    } else {
                        jsonObject.put(OP.Res, OP.Success);
                        jsonObject.put(OP.ObjId, entry.objId);
                        jsonObject.put(OP.W, entry.w);
                        jsonObject.put(OP.EncObj, entry.encryptedObject);
                        jsonObject.put(OP.STATUS, OP.StatusOk);
                    }
                    break;

                case "UpdateKey":
                    String delta = (String) request.get(OP.Delta);
                    boolean res = Storage.UpdateKey(name, new BigInteger(delta));

                    jsonObject.put(OP.Res, res);
                    jsonObject.put(OP.STATUS, OP.StatusOk);

                    break;

                default:
                    jsonObject.put(OP.Error, OP.InvalidRequestMethod);
                    jsonObject.put(OP.STATUS, OP.StatusNotFound);
            }
        } catch (Exception ex) {
            Storage.Log(Level.SEVERE, ex.getMessage());
            ex.printStackTrace();
        }

        return jsonObject.toJSONString();
    }
}
