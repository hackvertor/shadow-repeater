package burp.adaptive.learning.ai;

import burp.adaptive.learning.LearningExtension;
import burp.adaptive.learning.Utils;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.analysis.AttributeType;
import burp.api.montoya.http.message.responses.analysis.ResponseVariationsAnalyzer;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Set;

import static burp.adaptive.learning.LearningExtension.api;

public class OrganiseVectors {
    public static void organise(HttpRequestToBeSent req, JSONArray variations, JSONArray headersAndParameters, HttpResponseReceived[] repeaterResponses) {
        LearningExtension.executorService.submit(() -> {
            try {
                ResponseVariationsAnalyzer repeaterAnalyzer = api.http().createResponseVariationsAnalyzer();
                for (HttpResponseReceived repeaterResponse : repeaterResponses) {
                    repeaterAnalyzer.updateWith(repeaterResponse);
                }
                HttpRequestResponse baseRequestResponse = api.http().sendRequest(req);
                baseRequestResponse.annotations().setNotes("This is the base request/response");
                api.organizer().sendToOrganizer(baseRequestResponse);
                Set<AttributeType> invariantRepeaterResponseAttributes = repeaterAnalyzer.invariantAttributes();
                boolean foundInterestingItem = false;
                for(int i = 0; i < headersAndParameters.length(); i++) {
                    for(int k=0;k<3;k++) {
                        HttpRequest modifiedReq = null;
                        JSONObject headerParamObj = headersAndParameters.getJSONObject(i);
                        String type = headerParamObj.getString("type");
                        String name = headerParamObj.has("name") ? headerParamObj.getString("name") : "";
                        String controlValue = "";
                        HttpRequest controlReq = Utils.modifyRequest(req, type, name, controlValue);
                        HttpRequestResponse controlRequestResponse = api.http().sendRequest(controlReq);

                    }
                    for(int j = 0; j < variations.length(); j++) {
                        HttpRequest modifiedReq = null;
                        JSONObject headerParamObj = headersAndParameters.getJSONObject(i);
                        String type = headerParamObj.getString("type");
                        String name = headerParamObj.has("name") ? headerParamObj.getString("name") : "";
                        String vector = variations.getJSONObject(j).getString("vector");
                        modifiedReq = Utils.modifyRequest(req, type, name, vector);
                        if(modifiedReq != null) {
                            HttpRequestResponse requestResponse = api.http().sendRequest(modifiedReq);
                            ResponseVariationsAnalyzer analyzer = api.http().createResponseVariationsAnalyzer();
                            analyzer.updateWith(baseRequestResponse.response());
                            analyzer.updateWith(requestResponse.response());
                            Set<AttributeType> responseAttributesThatDiffer = analyzer.variantAttributes();
                            if(!responseAttributesThatDiffer.isEmpty()) {
                                StringBuilder notes = new StringBuilder();
                                notes.append("Variations: ").append(responseAttributesThatDiffer.size());
                                notes.append(System.lineSeparator());
                                notes.append(System.lineSeparator());
                                notes.append("The response is different in the following ways");
                                notes.append(System.lineSeparator());
                                if(baseRequestResponse.response().statusCode() != requestResponse.response().statusCode()) {
                                    notes.append("Old status code: ").append(baseRequestResponse.response().statusCode());
                                    notes.append("New status code: ").append(requestResponse.response().statusCode());
                                }
                                for(AttributeType attributeType : responseAttributesThatDiffer) {
                                    if(invariantRepeaterResponseAttributes.contains(attributeType)) {
                                        continue;
                                    }
                                    notes.append(attributeType.name());
                                    notes.append(System.lineSeparator());
                                    foundInterestingItem = true;
                                }
                                if(foundInterestingItem) {
                                    requestResponse.annotations().setNotes(notes.toString());
                                    api.organizer().sendToOrganizer(requestResponse);
                                }
                            }
                        }
                    }
                }
                if(foundInterestingItem) {
                    api.logging().logToOutput("Found interesting items. Check the organiser to see the results.");
                }
            } catch (Throwable throwable) {
                StringWriter writer = new StringWriter();
                throwable.printStackTrace(new PrintWriter(writer));
                api.logging().logToError(writer.toString());
            }
        });
    }
}
