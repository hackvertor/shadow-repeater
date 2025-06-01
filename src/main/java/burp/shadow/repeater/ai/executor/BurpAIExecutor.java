package burp.shadow.repeater.ai.executor;

import burp.api.montoya.ai.chat.Message;
import burp.api.montoya.ai.chat.PromptOptions;
import burp.api.montoya.ai.chat.PromptResponse;
import burp.shadow.repeater.ai.AIExecutor;

import static burp.shadow.repeater.ShadowRepeaterExtension.api;

public class BurpAIExecutor implements AIExecutor {
    @Override
    public PromptResponse execute(double temperature, String systemMessage, String userMessage) {
        return api.ai().prompt().execute(PromptOptions.promptOptions().withTemperature(temperature), Message.systemMessage(systemMessage), Message.userMessage(userMessage));
    }
}
