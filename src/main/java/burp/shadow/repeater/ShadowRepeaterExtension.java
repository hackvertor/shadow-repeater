package burp.shadow.repeater;

import burp.BulkUtilities;
import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.shadow.repeater.ai.AI;
import burp.shadow.repeater.settings.Settings;
import burp.shadow.repeater.utils.Utils;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.EnhancedCapability;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;

import javax.swing.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ShadowRepeaterExtension implements BurpExtension, ExtensionUnloadingHandler, IBurpExtender {

    public static JFrame SettingsFrame = null;
    public static IBurpExtenderCallbacks callbacks;
    public static Settings generalSettings = null;
    public static String extensionName = "Shadow Repeater";
    public static String version = "v1.0.0";
    public static MontoyaApi api;
    public static int requestHistoryPos = 1;
    public static ArrayList<HttpRequest> requestHistory = new ArrayList<>();
    public static ArrayList<HttpResponse> responseHistory = new ArrayList<>();
    public static String lastHost = null;
    public static final ExecutorService executorService = Executors.newSingleThreadExecutor();
    public static String nothingToAnalyseMsg = "Nothing to analyse. "+ extensionName +" requires data changing in the request.";

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        ShadowRepeaterExtension.api = montoyaApi;
        api.extension().setName(extensionName);
        api.logging().logToOutput(extensionName+ " " + version);
        api.http().registerHttpHandler(new HttpHandler());
        api.userInterface().registerContextMenuItemsProvider(new ContextMenu());
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
        ShadowRepeaterExtension.callbacks = callbacks;
        new BulkUtilities(callbacks, new HashMap<>(), extensionName);
        generalSettings = new Settings("general", callbacks);
        Utils.registerGeneralSettings(generalSettings);
        generalSettings.load();
    }
}
