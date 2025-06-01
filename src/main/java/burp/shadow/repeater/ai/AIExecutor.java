package burp.shadow.repeater.ai;

import burp.api.montoya.ai.chat.PromptResponse;

public interface AIExecutor {
    public PromptResponse execute(double temperature, String systemMessage, String userMessage);
}
