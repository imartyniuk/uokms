package main.java.org.illiam.uokms;

import org.json.simple.parser.ParseException;

public interface IResponseProcessor {
    Object ProcessResponse(String response) throws ParseException;
}
