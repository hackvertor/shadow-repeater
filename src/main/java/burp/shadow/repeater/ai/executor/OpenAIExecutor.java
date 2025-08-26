package burp.shadow.repeater.ai.executor;

import burp.api.montoya.ai.chat.PromptResponse;
import burp.shadow.repeater.ai.AIExecutor;

import org.json.JSONArray;
import org.json.JSONObject;

import static burp.shadow.repeater.ShadowRepeaterExtension.api;
import static burp.shadow.repeater.ShadowRepeaterExtension.settings;

class OpenAIResponse implements PromptResponse {
    private String content;

    OpenAIResponse(String content) {
        this.content = content;
    }

    public String content() {
        return content;
    }
}

class Payload extends JSONObject {
    Payload(double temperature, String systemMessage, String userMessage, String model) {
        put("model", (model != null && model.length() > 0) ? model : OpenAIExecutor.DEFAULT_MODEL);
        put("temperature", temperature);

        JSONArray messages = new JSONArray();

        JSONObject message = new JSONObject();
        message.put("role", "user");
        message.put("content", userMessage);
        messages.put(message);

        message = new JSONObject();
        message.put("role", "system");
        message.put("content", systemMessage);
        messages.put(message);

        put("messages", messages);
    }
}

public class OpenAIExecutor implements AIExecutor {
    public static String DEFAULT_ENDPOINT = "https://api.openai.com/v1/responses";
    public static String DEFAULT_MODEL = "o4-mini";

    @Override
    public PromptResponse execute(double temperature, String systemMessage, String userMessage) {
        try {
            String apiKey = settings.getString("OpenAI API key");
            String endpoint = settings.getString("OpenAI endpoint");
            String model = settings.getString("OpenAI model");

            Payload payload = new Payload(temperature, systemMessage, userMessage, model);

            java.net.http.HttpClient client = java.net.http.HttpClient.newHttpClient();
            java.net.http.HttpRequest request;
            java.net.http.HttpResponse<String> response;

            request = java.net.http.HttpRequest.newBuilder()
                .uri(java.net.URI.create(endpoint != null && endpoint.length() > 0 ? endpoint : DEFAULT_ENDPOINT))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + apiKey)
                .POST(java.net.http.HttpRequest.BodyPublishers.ofString(payload.toString()))
                .build();

            response = client.send(request, java.net.http.HttpResponse.BodyHandlers.ofString());

            int status = response.statusCode();
            String body = response.body();

            if (status != 200) {
                throw new Exception("Received response: " + status + " body: " + body);
            }

            // Parse the assistant content
            JSONObject jsonResponse = new JSONObject(body);
            JSONArray choices = jsonResponse.getJSONArray("choices");
            String result = null;
            for (int i = 0; i < choices.length(); i++) {
                JSONObject choice = choices.getJSONObject(i);
                JSONObject messageObj = choice.getJSONObject("message");
                if ("assistant".equals(messageObj.optString("role"))) {
                    result = messageObj.optString("content");
                    break;
                }
            }

            return new OpenAIResponse(result);
        } catch (Exception e) {
            api.logging().logToError(e);
            return new OpenAIResponse("");
        }
    }
}
