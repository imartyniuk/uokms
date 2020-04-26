package main.java.org.illiam.uokms;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

public class ConfigLoader {

    public static JSONObject LoadConfig(String configFile) {
        try {
            ClassLoader classLoader = new ConfigLoader().getClass().getClassLoader();
            InputStream is = classLoader.getResourceAsStream(configFile);
            BufferedReader br = new BufferedReader(new InputStreamReader(is));

            StringBuilder sb = new StringBuilder();
            String text;
            while((text = br.readLine()) != null) {
                sb.append(text);
            }

            JSONParser jsonParser = new JSONParser();
            return (JSONObject) jsonParser.parse(sb.toString());

        } catch (IOException | ParseException ex) {
            ex.printStackTrace();
            System.exit(1);
        }

        return null;
    }
}
