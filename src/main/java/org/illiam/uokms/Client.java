package org.illiam.uokms;

import org.json.simple.JSONObject;

import java.io.*;
import java.net.Socket;
import java.util.UUID;
import java.util.logging.Logger;

public class Client {

    private static Logger LOG = Logger.getLogger(Client.class.getName());

    private static int kmsPort = 9809;
    private static int stsPort = 9708;

    private static String kmsHost = "localhost";
    private static String stsHost = "localhost";

    private static final String packetEnd = "<FIN>";

    private UUID uuid;
    private Socket kmsSocket;

    public static void main(String[] args) {
        parseArgs(args);

        Client client = new Client();
        client.runKms(kmsHost, kmsPort);
    }

    private Client() {
        uuid = UUID.randomUUID();
        LOG.info(String.format("Created a client with an id: %s", uuid.toString()));
    }


    private static void parseArgs(String[] args) {
        if (args.length > 0) {
            kmsPort = Integer.parseInt(args[0]);
            LOG.info(String.format("Connecting to KMS on port %d", kmsPort));
        }

        if (args.length > 1) {
            stsPort = Integer.parseInt(args[1]);
            LOG.info(String.format("Connection to STS on port %d", stsPort));
        }
    }

    private void runKms(String kmsHost, int kmsPort) {
        try {
            kmsSocket = new Socket(kmsHost, kmsPort);

            sendMessage(kmsSocket, this.genGetDomainRequest());
            String msg = receiveMessage(kmsSocket);
            LOG.info(String.format("Received response: %s", msg));

            kmsSocket.close();

        } catch (IOException ex) {
            LOG.severe(String.format("Error running client: %s", ex.getMessage()));
            System.exit(1);
        }
    }

    private static void sendMessage(Socket socket, String msg) throws IOException {
        OutputStream os = socket.getOutputStream();
        PrintWriter pw = new PrintWriter(os, true);

        System.out.println(msg);
        pw.println(msg);
        pw.println(packetEnd);
    }

    private static String receiveMessage(Socket socket) throws IOException {
        InputStream is = socket.getInputStream();
        BufferedReader br = new BufferedReader(new InputStreamReader(is));

        StringBuilder msg = new StringBuilder();
        String text;
        do {
            text = br.readLine();
            msg.append(text);
        } while(!text.equals(packetEnd));

        return msg.toString();
    }

    private String genGetDomainRequest() {
        JSONObject jsonObject = new JSONObject();

        jsonObject.put("name", "client-"+this.uuid.toString());
        jsonObject.put("method", "GetDomainParameters");

        return jsonObject.toJSONString();
    }
}
