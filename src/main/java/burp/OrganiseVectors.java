package burp;

import burp.api.montoya.http.message.responses.HttpResponse;
import burp.shadow.repeater.ShadowRepeaterExtension;
import burp.shadow.repeater.ai.VectorReducer;
import burp.shadow.repeater.utils.Utils;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.HashSet;
import java.util.Set;

import static burp.shadow.repeater.ShadowRepeaterExtension.*;

public class OrganiseVectors {
    public static boolean checkForDifferences(JSONArray vectors, HttpRequestResponse baseRequestResponse, CustomResponseGroup responsesAnalyser, HttpRequest req, String type, String name) {
        for(int j = 0; j < vectors.length(); j++) {
            HttpRequest modifiedReq = null;
            String vector = vectors.getJSONObject(j).getString("vector");
            modifiedReq = Utils.modifyRequest(req, type, name, vector);
            if(modifiedReq != null) {
                HttpRequestResponse requestResponse = api.http().sendRequest(modifiedReq);
                if(!responsesAnalyser.matches(requestResponse)) {
                    api.organizer().sendToOrganizer(baseRequestResponse);
                    String notes = "The response is different in the following ways" +
                            System.lineSeparator() +
                            responsesAnalyser.describeDiff(requestResponse);
                    requestResponse.annotations().setNotes(notes);
                    api.organizer().sendToOrganizer(requestResponse);
                    api.logging().logToOutput("Found an interesting item. Check the organiser to see the results.");
                    return true;
                }
            }
        }
        return false;
    }
    public static void organise(HttpRequest req, JSONArray variations, JSONArray headersAndParameters, HttpResponse[] repeaterResponses, boolean shouldReduceVectors) {
        ShadowRepeaterExtension.executorService.submit(() -> {
            boolean debugOutput = settings.getBoolean("Debug output");
            try {
                HttpRequestResponse baseRequestResponse = api.http().sendRequest(req);
                baseRequestResponse.annotations().setNotes("This is the base request/response");
                Set<String> testedParams = new HashSet<>();
                for(int i = 0; i < headersAndParameters.length(); i++) {
                    JSONObject headerParamObj = headersAndParameters.getJSONObject(i);
                    String type = headerParamObj.getString("type");
                    String name = headerParamObj.has("name") ? headerParamObj.getString("name") : "";
                    CustomResponseGroup responsesAnalyser = new CustomResponseGroup(Utils::calculateFingerprint, baseRequestResponse);
                    if(testedParams.contains(name+type)) {
                        continue;
                    }
                    testedParams.add(name+type);
                    if(debugOutput) {
                        api.logging().logToOutput("Trying random values");
                    }
                    for(int k=1;k<=4;k++) {
                        try {
                            String controlValue = Utils.randomString(k * 2);
                            if(k < 3) {
                                controlValue += "  ";
                            }
                            HttpRequest controlReq = Utils.modifyRequest(req, type, name, controlValue);
                            HttpRequestResponse controlRequestResponse = api.http().sendRequest(controlReq);
                            responsesAnalyser.add(controlRequestResponse);
                        } catch (RuntimeException e) {
                            api.logging().logToError("Invalid control value length");
                        }

                    }
                    if(debugOutput) {
                        api.logging().logToOutput("Trying variations");
                    }

                    boolean foundDifference = checkForDifferences(variations, baseRequestResponse, responsesAnalyser, req, type, name);
                    if(!foundDifference && shouldReduceVectors) {
                        if(debugOutput) {
                            api.logging().logToOutput("Trying vector reduction");
                        }
                        JSONArray reducedVectors = VectorReducer.reduce(variations, debugOutput);
                        if(reducedVectors != null && !reducedVectors.isEmpty()) {
                            checkForDifferences(reducedVectors, baseRequestResponse, responsesAnalyser, req, type, name);
                        }

                    }
                }
            } catch (Throwable throwable) {
                StringWriter writer = new StringWriter();
                throwable.printStackTrace(new PrintWriter(writer));
                api.logging().logToError(writer.toString());
            } finally {
                api.logging().logToOutput("Complete.");
                api.logging().logToOutput("------");
            }
        });
    }
}
