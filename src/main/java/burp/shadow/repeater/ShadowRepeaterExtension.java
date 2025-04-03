package burp.shadow.repeater;

import burp.BulkUtilities;
import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.api.montoya.core.Registration;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.ui.hotkey.HotKeyContext;
import burp.shadow.repeater.ai.AI;
import burp.shadow.repeater.ai.VariationAnalyser;
import burp.shadow.repeater.settings.Settings;
import burp.shadow.repeater.utils.Utils;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.EnhancedCapability;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import org.json.JSONArray;

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
    public static String version = "v1.0.5";
    public static MontoyaApi api;
    public static boolean hasHotKey = false;
    public static HashMap<String, Integer> requestHistoryPos = new HashMap<>();
    public static HashMap<String, ArrayList<HttpRequest>> requestHistory = new HashMap<>();
    public static HashMap<String, ArrayList<HttpResponse>> responseHistory = new HashMap<>();
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
            api.logging().logToOutput("AI features are not available. This extension will not work without AI. You need to enable \"Use AI\" in the extension tab.");
        }
        api.userInterface().menuBar().registerMenu(Utils.generateMenuBar());
        Burp burp = new Burp(montoyaApi.burpSuite().version());
        if(burp.hasCapability(Burp.Capability.REGISTER_HOTKEY)) {
            Registration registration = montoyaApi.userInterface().registerHotKeyHandler(HotKeyContext.HTTP_MESSAGE_EDITOR, "Ctrl+Alt+A",
            event -> {
                if (event.messageEditorRequestResponse().isEmpty() || !AI.isAiSupported()) {
                    return;
                }
                MessageEditorHttpRequestResponse requestResponse = event.messageEditorRequestResponse().get();
                if(requestResponse.selectionContext().toString().equalsIgnoreCase("request")) {
                    String requestKey = Utils.generateRequestKey(requestResponse.requestResponse().request());
                    JSONArray headersAndParameters = RequestDiffer.generateHeadersAndParametersJson(requestHistory.get(requestKey).toArray(new HttpRequest[0]));
                    if (!headersAndParameters.isEmpty()) {
                        VariationAnalyser.analyse(headersAndParameters, requestResponse.requestResponse().request(), new HttpResponse[0]);
                    } else {
                        JOptionPane.showMessageDialog(null, nothingToAnalyseMsg);
                        api.logging().logToOutput(nothingToAnalyseMsg);
                    }
                    Utils.resetHistory(requestKey, false);
                }
            });
            if(registration.isRegistered()) {
                api.logging().logToOutput("Successfully registered hotkey handler");
                hasHotKey = true;
            } else {
                api.logging().logToError("Failed to register hotkey handler");
                hasHotKey = false;
            }
        }
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
