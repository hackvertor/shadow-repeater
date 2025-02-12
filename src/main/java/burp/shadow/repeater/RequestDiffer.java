package burp.shadow.repeater;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.*;
import java.util.stream.Collectors;

public class RequestDiffer {
    public static Set<String> headersToSkip = Set.of("Content-Length");
    public static JSONArray generateHeadersAndParametersJson(HttpRequest[] requests) {
        JSONArray result = new JSONArray();
        if (requests == null || requests.length == 0) return result;

        boolean allIdentical = areAllRequestsIdentical(requests);

        if (!allIdentical) {
            HttpRequest previous = null;
            for (int i = 0; i < requests.length; i++) {
                HttpRequest current = requests[i];
                if (i == 0) {
                    addAllItems(result, current);
                } else {
                    addDifferences(result, current, previous);
                }
                previous = current;
            }
            Set<String> inAll = intersectionOfAllRequests(requests);
            result = filterNeverChangedItems(result, inAll);
        }

        return result;
    }

    private static boolean areAllRequestsIdentical(HttpRequest[] requests) {
        for (int i = 1; i < requests.length; i++) {
            if (!requestsEquivalent(requests[0], requests[i])) return false;
        }
        return true;
    }

    private static boolean requestsEquivalent(HttpRequest a, HttpRequest b) {
        if (!a.pathWithoutQuery().equals(b.pathWithoutQuery())) return false;
        if (!a.headers().equals(b.headers())) return false;
        return parametersEqual(a.parameters(), b.parameters());
    }

    private static boolean parametersEqual(List<ParsedHttpParameter> listA, List<ParsedHttpParameter> listB) {
        if (listA.size() != listB.size()) return false;
        return parameterSet(listA).equals(parameterSet(listB));
    }

    private static Set<String> parameterSet(List<ParsedHttpParameter> params) {
        Set<String> set = new HashSet<>();
        for (ParsedHttpParameter p : params) {
            set.add(p.type() + "|" + p.name() + "|" + p.value());
        }
        return set;
    }

    private static void addAllItems(JSONArray result, HttpRequest request) {
        for (ParsedHttpParameter param : request.parameters()) {
            String type = parameterTypeText(param.type());
            if (!type.isEmpty()) {
                JSONObject obj = new JSONObject();
                obj.put("type", type);
                obj.put("name", param.name());
                obj.put("value", param.value());
                result.put(obj);
            }
        }
        String path = request.pathWithoutQuery();
        if (path.length() > 1) {
            JSONObject pathObj = new JSONObject();
            pathObj.put("type", "PATH");
            pathObj.put("value", path);
            result.put(pathObj);
        }
        List<HttpHeader> headers = new ArrayList<>(request.headers());
        if (!headers.isEmpty()) headers.remove(0);
        for (HttpHeader h : headers) {
            if(headersToSkip.contains(h.name())) {
                continue;
            }
            JSONObject headerObj = new JSONObject();
            headerObj.put("type", "header");
            headerObj.put("name", h.name());
            headerObj.put("value", h.value());
            result.put(headerObj);
        }
    }

    private static void addDifferences(JSONArray result, HttpRequest current, HttpRequest previous) {
        String curPath = current.pathWithoutQuery();
        String prevPath = previous.pathWithoutQuery();
        if (!curPath.equals(prevPath)) {
            JSONObject pathObj = new JSONObject();
            pathObj.put("type", "PATH");
            pathObj.put("value", curPath);
            result.put(pathObj);
        }
        Set<String> curParams = parameterSet(current.parameters());
        Set<String> prevParams = parameterSet(previous.parameters());
        for (String curParam : curParams) {
            if (!prevParams.contains(curParam)) {
                String[] parts = curParam.split("\\|", 3);
                JSONObject obj = new JSONObject();
                obj.put("type", parameterTypeText(HttpParameterType.valueOf(parts[0])));
                obj.put("name", parts[1]);
                obj.put("value", parts[2]);
                result.put(obj);
            }
        }
        List<String> curHeaders = current.headers().stream().map((header) -> header.name() + ":" + header.value()).collect(Collectors.toList());
        List<String> prevHeaders = previous.headers().stream().map((header) -> header.name() + ":" + header.value()).collect(Collectors.toList());
        if (!curHeaders.isEmpty()) curHeaders.remove(0);
        if (!prevHeaders.isEmpty()) prevHeaders.remove(0);
        Set<String> curHeadersSet = new HashSet<>(curHeaders);
        Set<String> prevHeadersSet = new HashSet<>(prevHeaders);
        for (String header : curHeadersSet) {
            if (!prevHeadersSet.contains(header)) {
                String[] headerParts = header.split(":", 2);
                if(headerParts.length > 0) {
                    JSONObject headerObj = new JSONObject();
                    headerObj.put("type", "header");
                    headerObj.put("name", headerParts[0]);
                    if(headerParts.length > 1) {
                        headerObj.put("value", headerParts[1]);
                    } else {
                        headerObj.put("value", "");
                    }
                    if(!headersToSkip.contains(headerObj.getString("name"))) {
                        result.put(headerObj);
                    }
                }
            }
        }
    }

    private static String parameterTypeText(HttpParameterType type) {
        return switch (type) {
            case BODY -> "BODY";
            case COOKIE -> "COOKIE";
            case JSON -> "JSON";
            case URL -> "URL";
            default -> "";
        };
    }

    private static Set<String> buildRequestSet(HttpRequest req) {
        Set<String> set = new HashSet<>();
        for (ParsedHttpParameter p : req.parameters()) {
            String t = parameterTypeText(p.type());
            if (!t.isEmpty()) {
                set.add(t + "|" + p.name() + "|" + p.value());
            }
        }
        String path = req.pathWithoutQuery();
        if (path.length() > 1) {
            set.add("PATH|" + path);
        }
        List<HttpHeader> headers = new ArrayList<>(req.headers());
        if (!headers.isEmpty()) headers.remove(0);
        for (HttpHeader h : headers) {
            set.add("header|" + h.name() + "|" + h.value());
        }
        return set;
    }

    private static Set<String> intersectionOfAllRequests(HttpRequest[] requests) {
        Set<String> intersection = null;
        for (HttpRequest r : requests) {
            Set<String> current = buildRequestSet(r);
            if (intersection == null) {
                intersection = new HashSet<>(current);
            } else {
                intersection.retainAll(current);
            }
            if (intersection.isEmpty()) break;
        }
        return intersection == null ? new HashSet<>() : intersection;
    }

    private static JSONArray filterNeverChangedItems(JSONArray result, Set<String> inAll) {
        JSONArray filtered = new JSONArray();
        for (int i = 0; i < result.length(); i++) {
            JSONObject obj = result.getJSONObject(i);
            String type = obj.optString("type");
            String name = obj.optString("name", "");
            String value = obj.optString("value", "");
            String key;
            if ("PATH".equals(type)) {
                key = type + "|" + value;
            } else {
                key = type + "|" + name + "|" + value;
            }
            if (!inAll.contains(key)) {
                filtered.put(obj);
            }
        }
        return filtered;
    }
}
