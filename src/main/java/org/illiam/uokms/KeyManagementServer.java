package main.java.org.illiam.uokms;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.logging.Level;

public class KeyManagementServer {

    /**
     * Members that provide server functionality.
     * **/
    private final int port;
    private final String stsHost;
    private final int stsPort;
    private ServerSocket serverSocket;

    private final int runPeriod;
    private final int updPeriod;

    public KeyManagementServer(int port, String stsHost, int stsPort, int runPeriod, int updPeriod) {
        this.port = port;
        this.stsHost = stsHost;
        this.stsPort = stsPort;
        this.runPeriod = runPeriod;
        this.updPeriod = updPeriod;
    }

    public void Start() {
        try {
            serverSocket = new ServerSocket(port);
            KeyManager.Log(Level.INFO, String.format("The server is listening on port %d", port));

            new KeyUpdaterThread(runPeriod, updPeriod, stsHost, stsPort).start();

            while (true) {
                Socket socket = serverSocket.accept();
                new KeyManagementServerThread(socket).start();
            }

        } catch (IOException ex) {
            KeyManager.Log(Level.SEVERE, ex.getMessage());
        }
    }
}
