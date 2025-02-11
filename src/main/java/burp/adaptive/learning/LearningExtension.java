package burp.adaptive.learning;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.EnhancedCapability;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.responses.analysis.ResponseVariationsAnalyzer;

import java.util.ArrayList;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class LearningExtension implements BurpExtension, ExtensionUnloadingHandler {

    public static MontoyaApi api;
    public static int amountOfVariations = 10;
    public static int maxAmountOfRequests = 5;
    public static int requestHistoryPos = 0;
    public static ArrayList<HttpRequestToBeSent> requestHistory = new ArrayList<>();
    public static ArrayList<HttpResponseReceived> responseHistory = new ArrayList<>();
    public static final ExecutorService executorService = Executors.newSingleThreadExecutor();

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        String extensionName = "Adaptive Learning";
        LearningExtension.api = montoyaApi;
        api.extension().setName(extensionName);
        api.logging().logToOutput(extensionName+ " v1.0");
        api.http().registerHttpHandler(new HttpHandler());
        api.extension().registerUnloadingHandler(this);
    }

    @Override
    public Set<EnhancedCapability> enhancedCapabilities() {
        return Set.of(EnhancedCapability.AI_FEATURES);
    }

    @Override
    public void extensionUnloaded() {
        executorService.shutdown();
    }
}
