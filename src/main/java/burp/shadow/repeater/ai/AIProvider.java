package burp.shadow.repeater.ai;

import burp.shadow.repeater.ShadowRepeaterExtension;
import burp.shadow.repeater.ai.executor.BurpAIExecutor;
import burp.shadow.repeater.ai.executor.OpenAIExecutor;
import burp.shadow.repeater.settings.InvalidTypeSettingException;
import burp.shadow.repeater.settings.UnregisteredSettingException;

public class AIProvider {
    public static AIExecutor acquire() {
        AIProviderType aiProvider;
        try {
            aiProvider = AIProviderType.valueOf(ShadowRepeaterExtension.generalSettings.getStringEnum("aiProvider"));
        } catch (UnregisteredSettingException | InvalidTypeSettingException e) {
            aiProvider = AIProviderType.BurpAI;
        }

        return switch (aiProvider) {
            case AIProviderType.OpenAI -> new OpenAIExecutor();
            default -> new BurpAIExecutor(); // Return Burp AI by default
        };
    };
}
