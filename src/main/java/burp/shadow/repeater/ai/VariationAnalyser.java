package burp.shadow.repeater.ai;

import burp.OrganiseVectors;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.shadow.repeater.ShadowRepeaterExtension;
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
                int maxVariationAmount = settings.getInteger("Maximum variation amount");
                String additionalInstructions = settings.getString("Additional LLM instructions");
                boolean shouldReduceVectors = settings.getBoolean("Reduce vectors");
                boolean debugAi = settings.getBoolean("Debug AI");
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
                        You should be creative when coming up with your variations.
                        You should avoid making up and spoofing domains.
                        Check for any patterns that align with RFC specifications.
                        If an RFC pattern is detected, focus the analysis on its compliance with the specification when producing variations.
                        Do not use example domains, you should always use the existing domains in the data your analyzing.
                        What are the structural differences between the vectors in this dataset? 
                        - Identify other possible variations that could follow the same pattern.
                        - Extract common patterns from this data and generate equivalent vectors used in other contexts.
                        Additional instructions:
                        """
                        +additionalInstructions+"\n"+
                        """
                        Here is a list of headers and parameters for you to analyse in JSON:
                        """);

                ai.setPrompt(headersAndParameters.toString());
                ai.setTemperature(1.0);
                if(debugAi) {
                    api.logging().logToOutput("Sending information to the AI");
                }
                String response = ai.execute();
                try {
                    String[] vectors = response.split("\n");
                    JSONArray variations = new JSONArray();
                    for (String vector : vectors) {
                        JSONObject variation = new JSONObject();
                        variation.put("vector", vector.trim());
                        variations.put(variation);
                    }
                    if(debugAi) {
                        api.logging().logToOutput("Variations found:\n" + variations);
                    }
                    OrganiseVectors.organise(req, variations, headersAndParameters, repeaterResponses, shouldReduceVectors);
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
