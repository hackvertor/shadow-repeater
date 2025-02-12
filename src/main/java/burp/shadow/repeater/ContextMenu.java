package burp.shadow.repeater;

import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.shadow.repeater.ai.VariationAnalyser;
import burp.shadow.repeater.settings.Settings;
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

            JMenuItem sendToItem = new JMenuItem("Send to " + extensionName);

            HttpRequestResponse requestResponse = event.messageEditorRequestResponse().isPresent() ? event.messageEditorRequestResponse().get().requestResponse() : event.selectedRequestResponses().getFirst();
            sendToItem.addActionListener(l -> {
                JSONArray headersAndParameters = RequestDiffer.generateHeadersAndParametersJson(requestHistory.toArray(new HttpRequest[0]));
                if (!headersAndParameters.isEmpty()) {
                    VariationAnalyser.analyse(headersAndParameters, requestResponse.request(), new HttpResponseReceived[0]);
                } else {
                    JOptionPane.showMessageDialog(null, nothingToAnalyseMsg);
                    api.logging().logToOutput(nothingToAnalyseMsg);
                }
            });
            menuItemList.add(sendToItem);
            JMenuItem settings = new JMenuItem("Settings");
            settings.addActionListener(e -> Settings.showSettingsWindow());
            menuItemList.add(settings);
            return menuItemList;
        }

        return null;
    }
}
