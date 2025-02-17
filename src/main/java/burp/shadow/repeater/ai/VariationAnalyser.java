package burp.shadow.repeater.ai;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.shadow.repeater.ShadowRepeaterExtension;
import burp.shadow.repeater.settings.InvalidTypeSettingException;
import burp.shadow.repeater.settings.UnregisteredSettingException;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.PrintWriter;
import java.io.StringWriter;

import static burp.shadow.repeater.ShadowRepeaterExtension.*;

public class VariationAnalyser {
    public static void analyse(JSONArray headersAndParameters, HttpRequest req, HttpResponse[] repeaterResponses) {
        ShadowRepeaterExtension.executorService.submit(() -> {
            try {
                int maxVariationAmount;
                try {
                    maxVariationAmount = ShadowRepeaterExtension.generalSettings.getInteger("maxVariationAmount");
                } catch (UnregisteredSettingException | InvalidTypeSettingException e) {
                    api.logging().logToError("Error loading settings:" + e);
                    throw new RuntimeException(e);
                }
                api.logging().logToOutput("------");
                api.logging().logToOutput("Analysing:\n" + headersAndParameters.toString() + "\n");
                AI ai = new AI();
                ai.setBypassRateLimit(true);
                ai.setSystemMessage("""
                        You are a web security expert.
                        Your job is to analyze the JSON given to you and look for variations of what's being tested.
                        You should return list of""" + " " + maxVariationAmount + " vectors separated by new lines." + """                       
                        Return **only vectors separated by new lines**. No markdown, no code blocks, and no extra text.
                        Do not output markdown.
                        Do not describe anything. Do not explain anything.
                        You should be creative and imagine a WAF blocking the vector and come up with creative ways of bypassing it.
                        You should avoid making up and spoofing domains.
                        Check for any patterns that align with RFC specifications.
                        If an RFC pattern is detected, focus the analysis on its compliance with the specification when producing variations.
                        Do not use example domains, you should always use the existing domains in the data your analyzing.
                        Here is a list of headers and parameters for you to analyse in JSON:
                        """);

                ai.setPrompt(headersAndParameters.toString());
                ai.setTemperature(1.0);
                api.logging().logToOutput("Sending information to the AI");
                String response = ai.execute();
                try {
                    String[] vectors = response.split("\n");
                    JSONArray variations = new JSONArray();
                    for (String vector : vectors) {
                        JSONObject variation = new JSONObject();
                        variation.put("vector", vector);
                        variations.put(variation);
                    }
                    api.logging().logToOutput("Variations found:\n" + variations);
                    OrganiseVectors.organise(req, variations, headersAndParameters, repeaterResponses);
                } catch (JSONException e) {
                    api.logging().logToError("The AI returned invalid JSON");
                }
            } catch (Throwable throwable) {
                StringWriter writer = new StringWriter();
                throwable.printStackTrace(new PrintWriter(writer));
                api.logging().logToError(writer.toString());
            }
        });
    }
}
