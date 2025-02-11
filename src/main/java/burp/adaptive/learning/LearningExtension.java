package burp.adaptive.learning;

import burp.BulkUtilities;
import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.adaptive.learning.ai.AI;
import burp.adaptive.learning.settings.Settings;
import burp.adaptive.learning.utils.Utils;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.EnhancedCapability;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.responses.analysis.ResponseVariationsAnalyzer;

import javax.swing.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class LearningExtension implements BurpExtension, ExtensionUnloadingHandler, IBurpExtender {

    public static JFrame SettingsFrame = null;
    public static IBurpExtenderCallbacks callbacks;
    public static Settings generalSettings = null;
    public static String extensionName = "Adaptive Learning";
    public static MontoyaApi api;
    public static int requestHistoryPos = 1;
    public static ArrayList<HttpRequestToBeSent> requestHistory = new ArrayList<>();
    public static ArrayList<HttpResponseReceived> responseHistory = new ArrayList<>();
    public static String lastHost = null;
    public static final ExecutorService executorService = Executors.newSingleThreadExecutor();

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        LearningExtension.api = montoyaApi;
        api.extension().setName(extensionName);
        api.logging().logToOutput(extensionName+ " v1.0");
        api.http().registerHttpHandler(new HttpHandler());
        api.extension().registerUnloadingHandler(this);
        if(!AI.isAiSupported()) {
            api.logging().logToOutput("AI features are not available. You need to enable \"Use AI\" in the extension tab.");
        }
        api.userInterface().menuBar().registerMenu(Utils.generateMenuBar());
    }

    @Override
    public Set<EnhancedCapability> enhancedCapabilities() {
        return Set.of(EnhancedCapability.AI_FEATURES);
    }

    @Override
    public void extensionUnloaded() {
        executorService.shutdown();
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        LearningExtension.callbacks = callbacks;
        new BulkUtilities(callbacks, new HashMap<>(), extensionName);
        generalSettings = new Settings("general", callbacks);
        Utils.registerGeneralSettings(generalSettings);
        generalSettings.load();
    }
}
