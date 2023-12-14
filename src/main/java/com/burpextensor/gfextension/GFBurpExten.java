package com.burpextensor.gfextension;

import burp.*;
import java.io.*;
import java.util.*;
import java.util.regex.*;
import com.google.gson.*;
import com.google.gson.reflect.TypeToken;

public class GFBurpExten implements IBurpExtender, IHttpListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private Map<String, List<Pattern>> regexPatterns = new HashMap<>();

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("GF Regex Pattern Detector");
        callbacks.registerHttpListener(this);

        // Load regex patterns from JSON files
        loadPatterns();
    }

    private void loadPatterns() {
        String[] patternFiles = {"debug_logic.json", "idor.json", "img-traversal.json", "interestingEXT.json", "interestingparams.json", "interestingsubs.json", "jsvar.json", "lfi.json", "rce.json", "redirect.json", "sqli.json", "ssrf.json", "ssti.json", "xss.json"};
        Gson gson = new Gson();
        for (String file : patternFiles) {
            try {
                InputStream in = getClass().getClassLoader().getResourceAsStream(file);
                BufferedReader reader = new BufferedReader(new InputStreamReader(in));
                List<String> filePatterns = gson.fromJson(reader, new TypeToken<List<String>>(){}.getType());
                List<Pattern> compiledPatterns = new ArrayList<>();
                for (String pattern : filePatterns) {
                    compiledPatterns.add(Pattern.compile(pattern));
                }
                regexPatterns.put(file, compiledPatterns);
            } catch (Exception e) {
                callbacks.printError("Error loading pattern file " + file + ": " + e.getMessage());
            }
        }
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (messageIsRequest) {
            // Extract and analyze request parameters
            IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
            List<IParameter> parameters = requestInfo.getParameters();
            for (IParameter parameter : parameters) {
                checkPattern(parameter);
            }
        }
    }

    private void checkPattern(IParameter parameter) {
        for (String patternKey : regexPatterns.keySet()) {
            for (Pattern pattern : regexPatterns.get(patternKey)) {
                Matcher matcher = pattern.matcher(parameter.getValue());
                if (matcher.find()) {
                    callbacks.issueAlert("Regex pattern match found: " + pattern + " in parameter " + parameter.getName());
                }
            }
        }
    }
}

