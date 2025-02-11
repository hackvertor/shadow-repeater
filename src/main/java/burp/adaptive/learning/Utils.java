package burp.adaptive.learning;

import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;

import static burp.adaptive.learning.LearningExtension.api;

public class Utils {
    public static HttpRequest modifyRequest(HttpRequestToBeSent req, String type, String name, String value) {
        return switch (type) {
            case "header" -> req.withRemovedHeader(name).withAddedHeader(name, value);
            case "URL", "BODY", "COOKIE", "JSON" -> {
                if (type.equals("URL")) {
                    value = api.utilities().urlUtils().encode(value);
                }
                yield req.withUpdatedParameters(HttpParameter.parameter(name, value, HttpParameterType.valueOf(type)));
            }
            default -> req;
        };
    }
}
