package burp.shadow.repeater;

import burp.shadow.repeater.ai.AI;
import burp.shadow.repeater.ai.VariationAnalyser;
import burp.shadow.repeater.settings.InvalidTypeSettingException;
import burp.shadow.repeater.settings.UnregisteredSettingException;
import burp.shadow.repeater.utils.Utils;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import org.json.JSONArray;

import static burp.shadow.repeater.ShadowRepeaterExtension.*;

public class HttpHandler implements burp.api.montoya.http.handler.HttpHandler {
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent req) {
        ToolSource toolSource = req.toolSource();
        String currentHost = req.httpService().host();
        if(AI.isAiSupported() && toolSource.isFromTool(ToolType.REPEATER)) {
            int amountOfRequests;
            try {
                amountOfRequests = ShadowRepeaterExtension.generalSettings.getInteger("amountOfRequests");
            } catch (UnregisteredSettingException | InvalidTypeSettingException e) {
                api.logging().logToError("Error loading settings:" + e);
                throw new RuntimeException(e);
            }


            if(lastHost != null && !currentHost.equals(lastHost)) {
               Utils.resetHistory();
            }

            if(requestHistoryPos >= amountOfRequests) {
                requestHistory.add(req);
                JSONArray headersAndParameters = RequestDiffer.generateHeadersAndParametersJson(requestHistory.toArray(new HttpRequestToBeSent[0]));
                if(!headersAndParameters.isEmpty()) {
                    VariationAnalyser.analyse(headersAndParameters, req, responseHistory.toArray(new HttpResponseReceived[0]));
                } else {
                    api.logging().logToOutput("Nothing to analyse. Adaptive learning requires data changing in the request.");
                }
                Utils.resetHistory();
            } else {
                requestHistory.add(req);
                requestHistoryPos++;
            }
            lastHost = currentHost;
        }
        return null;
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived resp) {
        responseHistory.add(resp);
        return null;
    }
}
