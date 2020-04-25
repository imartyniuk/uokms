package main.java.org.illiam.uokms;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.logging.Level;

public class KeyManagementServer {

    /**
     * Members that provide server functionality.
     * **/
    private static final int port = 9809;

    private ServerSocket serverSocket;

    public void Start() {
        try {
            serverSocket = new ServerSocket(port);
            KeyManager.Log(Level.INFO, String.format("The server is listening on port %d", port));

            new KeyUpdaterThread().start();
            KeyManager.Log(Level.INFO, "KeyUpdater thread has started");

            while (true) {
                Socket socket = serverSocket.accept();
                KeyManager.Log(Level.INFO, "New client is connected");

                new KeyManagementServerThread(socket).start();
            }

        } catch (IOException ex) {
            KeyManager.Log(Level.SEVERE, ex.getMessage());
        }
    }
}
