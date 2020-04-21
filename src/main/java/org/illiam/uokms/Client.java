package org.illiam.uokms;

import org.json.simple.JSONObject;

import java.io.IOException;
import java.net.Socket;
import java.util.logging.Logger;

public class Client {

    private static Logger LOG = Logger.getLogger(Client.class.getName());

    private static int kmsPort = 9809;
    private static int stsPort = 9708;

    private static String kmsHost = "localhost";
    private static String stsHost = "localhost";

    private static Socket kmsSocket;

    public static void main(String[] args) {
        parseArgs(args);

        String domainReq = genGetDomainRequest();
        System.out.println(domainReq);

        //runKms(kmsHost, kmsPort);
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

    private static void runKms(String kmsHost, int kmsPort) {
        try {
            kmsSocket = new Socket(kmsHost, kmsPort);

           //OutputStream os = kmsSocket.getOutputStream();
            //PrintWriter pw = new PrintWriter(os, true);

            //String domainReq = genGetDomainRequest();
            //System.out.println(domainReq);

            kmsSocket.close();

        } catch (IOException ex) {
            LOG.severe(String.format("Error running client: %s", ex.getMessage()));
            System.exit(1);
        }
    }

    private static String genGetDomainRequest() {
        JSONObject jsonObject = new JSONObject();

        jsonObject.put("name", "dummy");
        jsonObject.put("method", "GetDomainParameters");

        return jsonObject.toJSONString();
    }
}
