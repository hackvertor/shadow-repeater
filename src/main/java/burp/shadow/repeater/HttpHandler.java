package burp.shadow.repeater;

import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
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

import java.util.List;
import java.util.stream.Collectors;

import static burp.shadow.repeater.ShadowRepeaterExtension.*;

public class HttpHandler implements burp.api.montoya.http.handler.HttpHandler {
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent req) {
        ToolSource toolSource = req.toolSource();
        String requestKey = Utils.generateRequestKey(req);
        if(AI.isAiSupported() && toolSource.isFromTool(ToolType.REPEATER)) {
            int amountOfRequests;
            boolean autoInvoke;
            try {
                amountOfRequests = ShadowRepeaterExtension.generalSettings.getInteger("amountOfRequests");
                autoInvoke = ShadowRepeaterExtension.generalSettings.getBoolean("autoInvoke");
            } catch (UnregisteredSettingException | InvalidTypeSettingException e) {
                api.logging().logToError("Error loading settings:" + e);
                throw new RuntimeException(e);
            }

            api.logging().logToOutput("Repeater request " + requestHistoryPos.get(requestKey) + " of " + amountOfRequests);
            if(requestHistoryPos.get(requestKey) >= amountOfRequests) {
                requestHistory.get(requestKey).add(req);
                if(autoInvoke) {
                    JSONArray headersAndParameters = RequestDiffer.generateHeadersAndParametersJson(requestHistory.get(requestKey).toArray(new HttpRequest[0]));
                    if (!headersAndParameters.isEmpty()) {
                        VariationAnalyser.analyse(headersAndParameters, req, responseHistory.get(requestKey).toArray(new HttpResponse[0]));
                    } else {
                        api.logging().logToOutput(nothingToAnalyseMsg);
                    }
                }
                Utils.resetHistory(requestKey);
            } else {
                requestHistory.get(requestKey).add(req);
                requestHistoryPos.put(requestKey, requestHistoryPos.get(requestKey)+1);
            }
        }
        return null;
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived resp) {
        //responseHistory.add(resp);
        return null;
    }
}
