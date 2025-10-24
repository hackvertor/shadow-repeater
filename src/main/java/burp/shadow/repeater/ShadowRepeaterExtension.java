package burp.shadow.repeater;

import burp.BulkUtilities;
import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.api.montoya.core.Registration;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.ui.hotkey.HotKey;
import burp.api.montoya.ui.hotkey.HotKeyContext;
import burp.api.montoya.ui.hotkey.HotKeyHandler;
import burp.api.montoya.ui.settings.SettingsPanelBuilder;
import burp.api.montoya.ui.settings.SettingsPanelPersistence;
import burp.api.montoya.ui.settings.SettingsPanelSetting;
import burp.api.montoya.ui.settings.SettingsPanelWithData;
import burp.shadow.repeater.ai.AI;
import burp.shadow.repeater.ai.VariationAnalyser;
import burp.shadow.repeater.utils.Utils;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.EnhancedCapability;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import org.json.JSONArray;

import javax.swing.*;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ShadowRepeaterExtension implements BurpExtension, ExtensionUnloadingHandler, IBurpExtender {
    public static String extensionName = "Shadow Repeater";
    public static String version = "v1.2.1";
    public static MontoyaApi api;
    public static boolean hasHotKey = false;
    public static HashMap<String, Integer> requestHistoryPos = new HashMap<>();
    public static HashMap<String, ArrayList<HttpRequest>> requestHistory = new HashMap<>();
    public static HashMap<String, ArrayList<HttpResponse>> responseHistory = new HashMap<>();
    public static final ExecutorService executorService = Executors.newSingleThreadExecutor();
    public static String nothingToAnalyseMsg = "Nothing to analyse. "+ extensionName +" requires data changing in the request.";
    public static SettingsPanelWithData settings;

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
            registerAllHotkeys(montoyaApi, burp);
        }
        settings = SettingsPanelBuilder.settingsPanel()
                .withPersistence(SettingsPanelPersistence.USER_SETTINGS)
                .withTitle("Shadow Repeater Settings")
                .withDescription("""
                        Auto invoke - Runs Shadow Repeater automatically after the amount of requests specified.
                        Amount of requests - Amount of Repeater requests before invoking Shadow Repeater
                        Debug output - Outputs debug information to the console.
                        Debug AI - Make Shadow Repeater log all AI requests and responses to the console.
                        Reduce vectors - Should Shadow Repeater reduce the vectors?
                        Maximum variation amount - Maximum number of variations to create
                        Excluded headers - Comma separated list of headers to to exclude from analysis
                        Time difference threshold (ms) - Minimum time difference in milliseconds to detect timing-based attacks
                        Stop when first difference found - When Shadow Repeater finds a difference it should stop looking for more.
                        """)
                .withKeywords("Repeater", "Shadow", "Shadow Repeater settings")
                .withSettings(
                        SettingsPanelSetting.booleanSetting("Auto invoke", true),
                        SettingsPanelSetting.integerSetting("Amount of requests", 5),
                        SettingsPanelSetting.booleanSetting("Debug output", false),
                        SettingsPanelSetting.booleanSetting("Debug AI", false),
                        SettingsPanelSetting.booleanSetting("Reduce vectors", false),
                        SettingsPanelSetting.integerSetting("Maximum variation amount", 10),
                        SettingsPanelSetting.stringSetting("Excluded headers", "Authorization,Cookie,Content-Length,Connection"),
                        SettingsPanelSetting.integerSetting("Time difference threshold (ms)", 4000),
                        SettingsPanelSetting.booleanSetting("Stop when first difference found", false)
                )
                .build();
        api.userInterface().registerSettingsPanel(settings);
    }

    private void registerAllHotkeys(MontoyaApi montoyaApi, Burp burp) {
        List<HotkeyDefinition> hotkeys = Arrays.asList(
        new HotkeyDefinition("Analyse", "Ctrl+Alt+A", event -> {
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
        }));

        for (HotkeyDefinition hotkey : hotkeys) {
            registerHotkey(montoyaApi, burp, hotkey);
        }
    }

    private static class HotkeyDefinition {
        final String name;
        final String keyCombo;
        final HotKeyHandler handler;

        HotkeyDefinition(String name, String keyCombo, HotKeyHandler handler) {
            this.name = name;
            this.keyCombo = keyCombo;
            this.handler = handler;
        }
    }

    private void registerHotkey(MontoyaApi montoyaApi, Burp burp, HotkeyDefinition hotkey) {
        Registration registration;

        if(burp.hasCapability(Burp.Capability.REGISTER_HOTKEY_WITH_NAME)) {
            registration = montoyaApi.userInterface().registerHotKeyHandler(
                    HotKeyContext.HTTP_MESSAGE_EDITOR,
                    HotKey.hotKey(hotkey.name, hotkey.keyCombo),
                    hotkey.handler);
        } else {
            registration = montoyaApi.userInterface().registerHotKeyHandler(
                    HotKeyContext.HTTP_MESSAGE_EDITOR,
                    hotkey.keyCombo,
                    hotkey.handler);
        }

        if(registration.isRegistered()) {
            montoyaApi.logging().logToOutput("Successfully registered hotkey: " + hotkey.name + " (" + hotkey.keyCombo + ")");
            hasHotKey = true;
        } else {
            montoyaApi.logging().logToError("Failed to register hotkey: " + hotkey.name + " (" + hotkey.keyCombo + ")");
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
        new BulkUtilities(callbacks, new HashMap<>(), extensionName);
    }
}
