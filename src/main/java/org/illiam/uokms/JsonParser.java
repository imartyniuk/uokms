package main.java.org.illiam.uokms;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.util.logging.Logger;

public class JsonParser {

    private static Logger LOG = Logger.getLogger(JsonParser.class.getName());

    public static JSONObject getJson(String response) throws ParseException {
        JSONParser jsonParser = new JSONParser();
        JSONObject jsonObject = (JSONObject) jsonParser.parse(response);

        String status = (String) jsonObject.get(OP.STATUS);
        switch (status) {
            case OP.StatusOk:
                return jsonObject;
            case OP.StatusNotFound:
                LOG.warning(String.format("%s: %s", OP.Error, jsonObject.get(OP.Error)));
                return null;
            default:
                LOG.warning(String.format("Non-success code returned: %s", status));
                LOG.warning(String.format("%s: %s", OP.Error, jsonObject.get(OP.Error)));
                return null;
        }
    }
}
