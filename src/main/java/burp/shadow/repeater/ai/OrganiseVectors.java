package burp.shadow.repeater.ai;

import burp.CustomResponseGroup;
import burp.shadow.repeater.ShadowRepeaterExtension;
import burp.shadow.repeater.utils.Utils;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.PrintWriter;
import java.io.StringWriter;

import static burp.shadow.repeater.ShadowRepeaterExtension.*;

public class OrganiseVectors {
    public static void organise(HttpRequestToBeSent req, JSONArray variations, JSONArray headersAndParameters, HttpResponseReceived[] repeaterResponses) {
        ShadowRepeaterExtension.executorService.submit(() -> {
            try {
                HttpRequestResponse baseRequestResponse = api.http().sendRequest(req);
                baseRequestResponse.annotations().setNotes("This is the base request/response");
                for(int i = 0; i < headersAndParameters.length(); i++) {
                    CustomResponseGroup responsesAnalyser = new CustomResponseGroup(Utils::calculateFingerprint, baseRequestResponse);
                    api.logging().logToOutput("Trying random values");
                    for(int k=1;k<=5;k++) {
                        try {
                            JSONObject headerParamObj = headersAndParameters.getJSONObject(i);
                            String type = headerParamObj.getString("type");
                            String name = headerParamObj.has("name") ? headerParamObj.getString("name") : "";
                            String controlValue = Utils.randomString(k * 2);
                            HttpRequest controlReq = Utils.modifyRequest(req, type, name, controlValue);
                            HttpRequestResponse controlRequestResponse = api.http().sendRequest(controlReq);
                            responsesAnalyser.add(controlRequestResponse);
                        } catch (RuntimeException e) {
                            api.logging().logToError("Invalid control value length");
                        }

                    }
                    api.logging().logToOutput("Trying variations");
                    for(int j = 0; j < variations.length(); j++) {
                        HttpRequest modifiedReq = null;
                        JSONObject headerParamObj = headersAndParameters.getJSONObject(i);
                        String type = headerParamObj.getString("type");
                        String name = headerParamObj.has("name") ? headerParamObj.getString("name") : "";
                        String vector = variations.getJSONObject(j).getString("vector");
                        modifiedReq = Utils.modifyRequest(req, type, name, vector);
                        if(modifiedReq != null) {
                            HttpRequestResponse requestResponse = api.http().sendRequest(modifiedReq);
                            if(!responsesAnalyser.matches(requestResponse)) {
                                api.organizer().sendToOrganizer(baseRequestResponse);
                                StringBuilder notes = new StringBuilder();
                                notes.append("The response is different in the following ways");
                                notes.append(System.lineSeparator());
                                notes.append(responsesAnalyser.describeDiff(requestResponse));
                                requestResponse.annotations().setNotes(notes.toString());
                                api.organizer().sendToOrganizer(requestResponse);
                                api.logging().logToOutput("Found interesting items. Check the organiser to see the results.");
                                return;
                            }
                        }
                    }
                }
            } catch (Throwable throwable) {
                StringWriter writer = new StringWriter();
                throwable.printStackTrace(new PrintWriter(writer));
                api.logging().logToError(writer.toString());
            } finally {
                api.logging().logToOutput("Complete.");
            }
        });
    }
}
