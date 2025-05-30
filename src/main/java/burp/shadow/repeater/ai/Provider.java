package burp.shadow.repeater.ai;

public enum Provider {
    BurpAI("BurpAI"), OpenAI("OpenAI");

    private final String value;

    Provider(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }
}
