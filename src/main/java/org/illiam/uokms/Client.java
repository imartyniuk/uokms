package org.illiam.uokms;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import sun.rmi.runtime.Log;

import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.spec.DSAParameterSpec;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Client {

    private static Logger LOG = Logger.getLogger(Client.class.getName());

    private static int kmsPort = 9809;
    private static int stsPort = 9708;

    private static String kmsHost = "localhost";
    private static String stsHost = "localhost";

    private static final String packetEnd = "<FIN>";
    private static final String statusOK = "200";

    private UUID uuid;
    private Socket kmsSocket;

    /**
     * Crypto fields.
     * */
    private DSAParameterSpec dsaParameterSpec;

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


            processResponse(msg);

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

        return msg.toString().replace(packetEnd, "");
    }

    private void processResponse(String response) {
        try {
            JSONParser jsonParser = new JSONParser();
            JSONObject jsonObject = (JSONObject) jsonParser.parse(response);

            String status = (String) jsonObject.get("status");
            if (!status.equals(statusOK)) {
                LOG.warning(String.format("Non-success code returned: %s", status));
                return;
            }

            String p = (String) jsonObject.get("P");
            String q = (String) jsonObject.get("Q");
            String g = (String) jsonObject.get("G");

            BigInteger P = new BigInteger(p);
            BigInteger Q = new BigInteger(q);
            BigInteger G = new BigInteger(g);

            dsaParameterSpec = new DSAParameterSpec(P, Q, G);

            LOG.info("Successfully received domain parameters!");
            LOG.info(String.format("Value of P:\n%s\n", dsaParameterSpec.getP()));
            LOG.info(String.format("Value of Q:\n%s\n", dsaParameterSpec.getQ()));
            LOG.info(String.format("Value of G:\n%s\n", dsaParameterSpec.getG()));

        } catch (ParseException ex) {
            LOG.severe(String.format("Error processing response: %s", ex.getMessage()));
            ex.printStackTrace();
        }
    }

    private String genGetDomainRequest() {
        JSONObject jsonObject = new JSONObject();

        jsonObject.put("name", "client-"+this.uuid.toString());
        jsonObject.put("method", "GetDomainParameters");

        return jsonObject.toJSONString();
    }
}
