package burp.shadow.repeater.ai;

import burp.shadow.repeater.ai.executor.BurpAIExecutor;
import burp.shadow.repeater.ai.executor.OpenAIExecutor;

import static burp.shadow.repeater.ShadowRepeaterExtension.settings;

public class AIProvider {
    public static AIExecutor acquire() {
        AIProviderType aiProvider;
        try {
            aiProvider = AIProviderType.valueOf(settings.getString("AI provider"));
        } catch (Exception e) {
            aiProvider = AIProviderType.BurpAI;
        }

        return switch (aiProvider) {
            case AIProviderType.OpenAI -> new OpenAIExecutor();
            default -> new BurpAIExecutor(); // Return Burp AI by default
        };
    };
}
