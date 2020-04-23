package main.java.org.illiam.uokms;

import java.io.*;
import java.net.Socket;

public class Communicator {

    private static final String packetEnd = "<FIN>";

    public static void SendMessage(Socket socket, String msg) throws IOException {
        OutputStream os = socket.getOutputStream();
        PrintWriter pw = new PrintWriter(os, true);

        pw.println(msg);
        pw.println(packetEnd);
    }

    public static String ReceiveMessage(Socket socket) throws IOException {
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
}
