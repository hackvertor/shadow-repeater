package burp.adaptive.learning;

import burp.adaptive.learning.ai.AI;
import burp.adaptive.learning.ai.VariationAnalyser;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import org.json.JSONArray;

import java.util.ArrayList;

import static burp.adaptive.learning.LearningExtension.*;

public class HttpHandler implements burp.api.montoya.http.handler.HttpHandler {
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent req) {
        ToolSource toolSource = req.toolSource();
        if(AI.isAiSupported() && toolSource.isFromTool(ToolType.REPEATER)) {
            if(requestHistoryPos >= maxAmountOfRequests) {
                JSONArray headersAndParameters = RequestDiffer.generateHeadersAndParametersJson(requestHistory.toArray(new HttpRequestToBeSent[0]));
                if(!headersAndParameters.isEmpty()) {
                    VariationAnalyser.analyse(headersAndParameters, req, responseHistory.toArray(new HttpResponseReceived[0]));
                } else {
                    api.logging().logToOutput("Nothing to analyse. Adaptive learning requires data changing in the request.");
                }
                requestHistoryPos = 0;
                requestHistory = new ArrayList<>();
                responseHistory = new ArrayList<>();
            } else {
                requestHistory.add(req);
                requestHistoryPos++;
            }
        }
        return null;
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived resp) {
        responseHistory.add(resp);
        return null;
    }
}
