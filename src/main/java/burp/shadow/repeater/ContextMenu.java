package burp.shadow.repeater;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.shadow.repeater.ai.AI;
import burp.shadow.repeater.ai.VariationAnalyser;
import burp.shadow.repeater.settings.Settings;
import burp.shadow.repeater.utils.Utils;
import org.json.JSONArray;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

import static burp.shadow.repeater.ShadowRepeaterExtension.*;

public class ContextMenu implements ContextMenuItemsProvider {
    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event)
    {
        if (event.isFromTool(ToolType.REPEATER))
        {
            List<Component> menuItemList = new ArrayList<>();
            JMenuItem doAnalysisItem;
            Burp burp = new Burp(api.burpSuite().version());
            if(hasHotKey && burp.hasCapability(Burp.Capability.REGISTER_HOTKEY)) {
                doAnalysisItem = new JMenuItem("Do analysis (CTRL+ALT+A)");
            } else {
                doAnalysisItem = new JMenuItem("Do analysis");
            }
            doAnalysisItem.setEnabled(AI.isAiSupported());
            HttpRequestResponse requestResponse = event.messageEditorRequestResponse().isPresent() ? event.messageEditorRequestResponse().get().requestResponse() : event.selectedRequestResponses().getFirst();
            if(requestResponse.httpService() == null) {
                return null;
            }
            String requestKey = Utils.generateRequestKey(requestResponse.request());
            doAnalysisItem.addActionListener(e -> {
                JSONArray headersAndParameters = RequestDiffer.generateHeadersAndParametersJson(requestHistory.get(requestKey).toArray(new HttpRequest[0]));
                if (!headersAndParameters.isEmpty()) {
                    VariationAnalyser.analyse(headersAndParameters, requestResponse.request(), new HttpResponse[0]);
                } else {
                    JOptionPane.showMessageDialog(null, nothingToAnalyseMsg);
                    api.logging().logToOutput(nothingToAnalyseMsg);
                }
                Utils.resetHistory(requestKey, false);
            });
            menuItemList.add(doAnalysisItem);
            JMenuItem resetHistoryItem = new JMenuItem("Reset request history for this request");
            resetHistoryItem.setEnabled(AI.isAiSupported());
            resetHistoryItem.addActionListener(e -> Utils.resetHistory(requestKey, true));
            menuItemList.add(resetHistoryItem);
            JMenuItem settings = new JMenuItem("Settings");
            settings.addActionListener(e -> Settings.showSettingsWindow());
            menuItemList.add(settings);
            return menuItemList;
        }

        return null;
    }
}
