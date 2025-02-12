package burp.shadow.repeater.ai;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.shadow.repeater.ShadowRepeaterExtension;
import burp.shadow.repeater.settings.InvalidTypeSettingException;
import burp.shadow.repeater.settings.UnregisteredSettingException;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import org.json.JSONArray;
import org.json.JSONException;

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
                        You should return a JSON array of""" + " " + maxVariationAmount + " vectors." + """
                        The JSON structure should be:[{"vector":"$yourVariation"}].
                        If you cannot find a variation just return an empty array.
                        Your response must be a **valid JSON array of objects**. Ensure all string values inside the objects are properly escaped. This includes:
                        - Escaping double quotes (`"`) as `\\"`
                        - Escaping backslashes (`\\`) as `\\\\`
                        - Escaping newlines (`\\n`), tabs (`\\t`), and special characters
                        - Avoiding unescaped control characters

                        Return **only JSON**. No markdown, no code blocks, and no extra text.
                        You should be creative and imagine a WAF blocking the vector and come up with creative ways of bypassing it.
                        The vector you produce should be relevant the 
                        Here is a list of headers and parameters for you to analyse in JSON:
                        """);

                ai.setPrompt(headersAndParameters.toString());
                ai.setTemperature(1.0);
                api.logging().logToOutput("Sending information to the AI");
                String response = ai.execute();
                try {
                    JSONArray variations = new JSONArray(response);
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
