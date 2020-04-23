package main.java.org.illiam.uokms;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.util.logging.Logger;

public class JsonParser {

    private static Logger LOG = Logger.getLogger(JsonParser.class.getName());

    private static final String statusOK = "200";

    public static JSONObject getJson(String response) throws ParseException {
        JSONParser jsonParser = new JSONParser();
        JSONObject jsonObject = (JSONObject) jsonParser.parse(response);

        String status = (String) jsonObject.get("status");
        if (!status.equals(statusOK)) {
            LOG.warning(String.format("Non-success code returned: %s", status));
            return null;
        }

        return jsonObject;
    }
}
