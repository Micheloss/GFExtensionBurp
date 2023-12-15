package com.burpextensor.gfextension;

import burp.*;
import java.io.*;
import java.net.URL;
import java.util.*;
import java.util.regex.*;


import com.burpextensor.gfextension.pojo.JsonPattern;
import com.burpextensor.gfextension.pojo.CustomScanIssue;

import com.google.gson.*;
import com.google.gson.reflect.TypeToken;

public class GFBurpExten implements IBurpExtender, IHttpListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private Map<String, List<String>> regexPatterns = new HashMap<>();
	private IExtensionHelpers callbacksHelpers;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.callbacksHelpers = callbacks.getHelpers();

        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("GF Regex Pattern Detector");
        callbacks.registerHttpListener(this);

        // Load regex patterns from JSON files
        loadPatterns();
    }

    private void loadPatterns() {
        String[] patternFiles = {"debug_logic.json", "idor.json",  "interestingparams.json", "lfi.json", "rce.json", "redirect.json", "sqli.json", "ssrf.json", "ssti.json", "xss.json"};
        Gson gson = new Gson();
        for (String file : patternFiles) {
            try {
                callbacks.printOutput("Going to process " + file );
                
                InputStream inputStream = GFBurpExten.class.getClassLoader().getResourceAsStream(file);
                InputStreamReader reader = new InputStreamReader(inputStream);
                
                JsonPattern jsonPatterns = gson.fromJson(reader, JsonPattern.class);

/*
                InputStream in = GFBurpExten.class.getClassLoader().getResourceAsStream(file);
                BufferedReader reader = new BufferedReader(new InputStreamReader(in));
                
                JsonPattern jsonPatterns = gson.fromJson(reader, JsonPattern.class);
*/
                
                List<String> patterns = jsonPatterns.getPatterns();

                for (String pattern : patterns) {
                    callbacks.printOutput("Proccessed " + pattern + "");
                    //callbacks.printOutput("Proccessed " + pattern + " from " + file.split(".")[0]);

                }
                
                regexPatterns.put(file, patterns);
                
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
                checkPattern(parameter, messageInfo);
            }
        }
    }

    private void checkPattern(IParameter parameter, IHttpRequestResponse messageInfo) {
        for (String patternKey : regexPatterns.keySet()) {
            for (String pattern : regexPatterns.get(patternKey)) {
                //callbacks.printOutput("Found paramenter " +  pattern + " of type "+ parameter.getType());
            	if(parameter.getType() != IParameter.PARAM_COOKIE) {
            		 if (parameter.getName().toLowerCase().startsWith(pattern.split("=")[0])) {
                         //callbacks.issueAlert("Regex pattern match found: " + pattern + " in parameter " + parameter.getName());
                         callbacks.printOutput("Regex pattern match found: " + pattern + " from" + patternKey +" in parameter " + parameter.getName() + " of type "+ parameter.getType());
                         printIssue(messageInfo, parameter.getName(), patternKey);
                     }
            	}
               
            }
        }
    }
    
    private void printIssue(IHttpRequestResponse messageInfo, String parameter, String file) {
    	String url = callbacksHelpers.analyzeRequest(messageInfo).getUrl().toString();
    	if( !(url.contains(".js") || url.contains(".png") || url.contains(".css") || url.contains(".jpg") || url.contains(".jpeg") || url.contains(".js")) ) {
    		
	    	IHttpRequestResponse[] httpMessages = null; // Mensajes HTTP relacionados con el problema
	    	IHttpService httpService = messageInfo.getHttpService(); // Servicio HTTP relacionado
	
	    	
	    	byte[] request = messageInfo.getRequest();
	    	String requestString = helpers.bytesToString(request);
	    	
	    	int startOffset = requestString.indexOf(parameter);
	    	int endOffset = startOffset + parameter.length();
	    	
	    	List<int[]> requestHighlights = new ArrayList<>();

	    	if (startOffset != -1) { // Asegúrate de que el string fue encontrado
	    	    requestHighlights.add(new int[] { startOffset, endOffset });
	    	}
	    	
	    	IScanIssue newIssue = new CustomScanIssue(
	    		callbacksHelpers.analyzeRequest(messageInfo).getUrl(),
	    	    "[GF] Found problematic parameter",
	    	    "Low",
	    	    "Tentative",
	    	    "Found a parameter that might be problematic. \n Found parameter " + parameter + " . Test for " + file + " attacks",
	    	    "Test for problem",
	    	    new IHttpRequestResponse[] { callbacks.applyMarkers(messageInfo, requestHighlights, null)},
	    	    httpService,
	    	    "Found a parameter that might be problematic. \n Found parameter " + parameter + " . Test for " + file + " attacks"
	    	);
	
	    	callbacks.addScanIssue(newIssue);
    	}
    }
}

