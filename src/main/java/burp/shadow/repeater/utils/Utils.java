package burp.shadow.repeater.utils;

import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.shadow.repeater.ShadowRepeaterExtension;
import burp.shadow.repeater.settings.Settings;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;

import javax.swing.*;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static burp.shadow.repeater.ShadowRepeaterExtension.*;
import static burp.shadow.repeater.ShadowRepeaterExtension.responseHistory;

public class Utils {
    public static HttpRequest modifyRequest(HttpRequest req, String type, String name, String value) {
        return switch (type) {
            case "header" -> req.withRemovedHeader(name).withAddedHeader(name, value);
            case "URL", "BODY", "COOKIE", "JSON" -> {
                if ((type.equals("BODY") || type.equals("URL")) && !value.matches("%[a-fA-F0-9]{2}]")) {
                    value = api.utilities().urlUtils().encode(value);
                }
                yield req.withUpdatedParameters(HttpParameter.parameter(name, value, HttpParameterType.valueOf(type)));
            }
            default -> req;
        };
    }
    public static String randomString(int length) throws IllegalArgumentException {
        String CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        SecureRandom RANDOM = new SecureRandom();
        if (length <= 0) {
            throw new IllegalArgumentException("Length must be greater than 0");
        }
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(CHARACTERS.charAt(RANDOM.nextInt(CHARACTERS.length())));
        }

        return sb.toString();
    }
    public static HashMap<String, Object> calculateFingerprint(HttpRequestResponse resp) {
        String[] keys = new String[]{"\",\"", "true", "false", "\"\"", "[]", "</html>", "error", "exception", "invalid", "warning", "stack",
                "sql syntax", "divisor", "divide", "ora-", "division", "infinity", "<script", "<div", "<"
        };
        String[] newLines = new String[]{"\r" ,"\n", "\u2028", "\u2029"};
        String[] spaces = new String[]{" ", "\t", "\u00a0"};
        HashMap<String, Object> fingerprint = new HashMap<>();
        if (!resp.hasResponse()) {
            fingerprint.put("status", 0);
            return fingerprint;
        }
        String body = resp.response().bodyToString().toLowerCase();
        fingerprint.put("status", resp.response().statusCode());
        fingerprint.put("title", getTitle(body));
        for (String key : keys) {
            fingerprint.put(key, countString(body, key));
        }
        int newLineCount = 0;
        for (String newLine : newLines) {
            newLineCount += countString(body, newLine);
        }
        fingerprint.put("New lines", newLineCount);
        int spaceCount = 0;
        for (String space : spaces) {
            spaceCount += countString(body, space);
        }
        fingerprint.put("Spaces", spaceCount);
        return fingerprint;
    }

    static int countString(String input, String find) {
        return input.split(Pattern.quote(find), -1).length - 1;
    }

    static String getTitle(String body) {
        try {
            if (!body.contains("<title")) {
                return "";
            }
            return body.split("<title", 1)[1].split(">", 1)[1].split("<")[0];
        } catch (Exception e) {
            return "";
        }
    }
    public static void resetHistory(String key, boolean shouldDebug) {
        requestHistoryPos.put(key,1);
        requestHistory.put(key, new ArrayList<>());
        responseHistory.put(key, new ArrayList<>());
        if(shouldDebug) {
            api.logging().logToOutput("Request history reset");
        }
    }
    public static void registerGeneralSettings(Settings settings) {
        settings.registerBooleanSetting("autoInvoke", true, "Auto invoke after repeater requests", "Repeater settings", null);
        settings.registerBooleanSetting("shouldReduceVectors", false, "Attempt to reduce length of each vector if they fail", "Repeater settings", null);
        settings.registerIntegerSetting("amountOfRequests", 5, "Amount of requests before doing AI analysis (2-100)", "Repeater settings", 2, 100);
        settings.registerIntegerSetting("maxVariationAmount", 10, "Maximum amount of variations (1-100)", "Repeater settings", 1, 100);
        settings.registerBooleanSetting("debugOutput", false, "Print debug output", "General", null);
        settings.registerBooleanSetting("debugAi", false, "Debug AI requests/responses", "AI", null);

    }

    public static JFrame getSettingsWindowInstance() {
        if(SettingsFrame != null) {
            return SettingsFrame;
        }
        SettingsFrame = new JFrame();
        SettingsFrame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                SettingsFrame.setVisible(false);
                SettingsFrame.getContentPane().removeAll();
                SettingsFrame.getContentPane().setLayout(new BorderLayout());
            }
        });
        return SettingsFrame;
    }

    public static JMenu generateMenuBar() {
        JMenu menuBar = new JMenu(extensionName);
        JMenuItem settingsMenu = new JMenuItem("Settings");
        settingsMenu.addActionListener(e -> Settings.showSettingsWindow());
        menuBar.add(settingsMenu);
        return menuBar;
    }

    public static ImageIcon createImageIcon(String path, String description) {
        java.net.URL imgURL = ShadowRepeaterExtension.class.getResource(path);
        if (imgURL != null) {
            return new ImageIcon(imgURL, description);
        } else {
            api.logging().logToError("Couldn't find file: " + path);
            return null;
        }
    }

    public static String generateRequestKey(HttpRequest req) {
        String currentHost = req.httpService().host();
        String paramNames = req.parameters().stream().map(ParsedHttpParameter::name).collect(Collectors.joining(","));
        String requestKey = currentHost + paramNames;
        if(!requestHistoryPos.containsKey(requestKey)) {
            requestHistoryPos.put(requestKey, 1);
            requestHistory.put(requestKey, new ArrayList<>());
            responseHistory.put(requestKey, new ArrayList<>());
        }
        return requestKey;
    }
}
