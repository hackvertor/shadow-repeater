package burp.shadow.repeater.ai;

import burp.api.montoya.ai.chat.Message;
import burp.api.montoya.ai.chat.PromptOptions;
import burp.api.montoya.ai.chat.PromptResponse;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static burp.shadow.repeater.ShadowRepeaterExtension.api;
import static burp.shadow.repeater.ShadowRepeaterExtension.settings;

public class AI {
    public static final String featureMessage = "This feature is only available on the AI version of Burp.";
    public static long lastExecutionTime = 0;
    public static long apiRequestLimitMS = 1000;
    private String systemMessage;
    private String prompt;
    private double temperature;
    private boolean bypassRateLimit = false;
    public void setBypassRateLimit(boolean bypassRateLimit) {
         this.bypassRateLimit = bypassRateLimit;
    }

    public void setSystemMessage(String systemMessage) {
         this.systemMessage = systemMessage;
    }

    public void setPrompt(String prompt) {
         this.prompt = prompt;
    }

    public void setTemperature(double temperature) {
        this.temperature = temperature;
    }

    public String getPrompt() {
         return this.prompt;
    }

    public static boolean isAiSupported() {
        return api != null && api.ai().isEnabled();
    }

    public String getSystemMessage() {
        return this.systemMessage;
    }

    public static String getHash(String input) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(input.getBytes());
        return new String(messageDigest.digest());
    }
    public String execute() {
        boolean debugAi = settings.getBoolean("Debug AI");

        if(!isAiSupported()) {
            throw new RuntimeException("Montoya AI API is not enabled. You need to enable use AI in the extension tab.");
        }
        if(!bypassRateLimit) {
            checkLastExecutionTime();
        }
        if(debugAi) {
            api.logging().logToOutput("System Prompt:" + this.systemMessage + "\n\n");
            api.logging().logToOutput("Prompt:" + this.prompt + "\n\n");
        }
        PromptResponse response = api.ai().prompt().execute(PromptOptions.promptOptions().withTemperature(this.temperature), Message.systemMessage(this.systemMessage), Message.userMessage(this.prompt));
        if(debugAi) {
            api.logging().logToOutput("AI Response:" + response.content() + "\n\n");
        }
        return response.content();
    }
    public void checkLastExecutionTime() {
        long now = System.currentTimeMillis();
        if(AI.lastExecutionTime > 0) {
            long diff = now - AI.lastExecutionTime;
            if(diff < AI.apiRequestLimitMS) {
                AI.lastExecutionTime = now;
                throw new RuntimeException("API request limit hit. Please wait a few seconds.");
            }
        }
        AI.lastExecutionTime = now;
    }
}
