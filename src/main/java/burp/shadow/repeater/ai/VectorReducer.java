package burp.shadow.repeater.ai;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Arrays;

import static burp.shadow.repeater.ShadowRepeaterExtension.api;

public class VectorReducer {
    public static JSONArray reduce(JSONArray vectors, boolean shouldDebugOutput) {
        try {
            if(shouldDebugOutput) {
                api.logging().logToOutput("Reducing vectors");
            }

            AI ai = new AI();
            ai.setBypassRateLimit(true);
            ai.setSystemMessage("""
                        You are a web security expert.
                        Your job is to analyze the JSON given to you and look for ways of making the vectors smaller.
                        Do not reduce any existing domain names.
                        You should always use the existing domains in the data your analyzing.
                        Return **only vectors separated by new lines**. No markdown, no code blocks, and no extra text.
                        Do not output markdown.
                        Do not describe anything. Do not explain anything.
                        Remove any duplicates from the response.
                        Here is a list of vectors for you to analyse in JSON:
                        """);

            ai.setPrompt(vectors.toString());
            ai.setTemperature(1.0);
            if(shouldDebugOutput) {
                api.logging().logToOutput("Sending existing vectors to the AI");
            }
            String response = ai.execute();
            try {
                String[] reducedVectors = response.split("\n");
                String[] uniqueVariations = Arrays.stream(reducedVectors)
                        .distinct()
                        .toArray(String[]::new);
                JSONArray variations = new JSONArray();
                for (String vector : uniqueVariations) {
                    JSONObject variation = new JSONObject();
                    variation.put("vector", vector);
                    variations.put(variation);
                }
                if(shouldDebugOutput) {
                    api.logging().logToOutput("Reduced vectors found:\n" + variations);
                }
                return variations;
            } catch (JSONException e) {
                api.logging().logToError("The AI returned invalid JSON");
            }
        } catch (Throwable throwable) {
            StringWriter writer = new StringWriter();
            throwable.printStackTrace(new PrintWriter(writer));
            api.logging().logToError(writer.toString());
        }
        return null;
    }
}
