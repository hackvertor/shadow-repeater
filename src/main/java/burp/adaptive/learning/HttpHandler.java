package burp.adaptive.learning;

import burp.adaptive.learning.ai.AI;
import burp.adaptive.learning.ai.VariationAnalyser;
import burp.adaptive.learning.settings.InvalidTypeSettingException;
import burp.adaptive.learning.settings.UnregisteredSettingException;
import burp.adaptive.learning.utils.Utils;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import org.json.JSONArray;

import static burp.adaptive.learning.LearningExtension.*;

public class HttpHandler implements burp.api.montoya.http.handler.HttpHandler {
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent req) {
        ToolSource toolSource = req.toolSource();
        String currentHost = req.httpService().host();
        if(AI.isAiSupported() && toolSource.isFromTool(ToolType.REPEATER)) {
            int amountOfRequests;
            try {
                amountOfRequests = LearningExtension.generalSettings.getInteger("amountOfRequests");
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
