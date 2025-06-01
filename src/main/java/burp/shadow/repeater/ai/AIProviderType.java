package burp.shadow.repeater.ai;

public enum AIProviderType {
    BurpAI("BurpAI"), OpenAI("OpenAI");

    private final String value;

    AIProviderType(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }
}
