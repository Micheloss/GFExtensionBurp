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
    private HashMap<String, List<String>> regexPatterns = new HashMap<>();
	private IExtensionHelpers callbacksHelpers;

	
	private ArrayList<String> wellKnownHeaders;
	
	private ArrayList<String>  alreadyReportedParameters;
	private ArrayList<String>  alreadyReportedHeaders;
	private ArrayList<String>  alreadyReportedCookies;

	
	
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.callbacksHelpers = callbacks.getHelpers();

        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("GF Regex Pattern Detector");
        callbacks.registerHttpListener(this);
        
        alreadyReportedParameters = new ArrayList<String>();
        alreadyReportedHeaders = new ArrayList<String>();
        alreadyReportedCookies = new ArrayList<String>();
        // Load regex patterns from JSON files
        loadPatterns();
    }

    private void loadPatterns() {
        
    	// Parameters
    	String[] patternFiles = {"debug_logic.json", "idor.json",  "interestingparams.json", "lfi.json", "rce.json", "redirect.json", "sqli.json", "ssrf.json", "ssti.json", "xss.json"};
        Gson gson = new Gson();
        for (String file : patternFiles) {
            try {
                callbacks.printOutput("Going to process " + file );
                
                InputStream inputStream = GFBurpExten.class.getClassLoader().getResourceAsStream(file);
                InputStreamReader reader = new InputStreamReader(inputStream);
                
                JsonPattern jsonPatterns = gson.fromJson(reader, JsonPattern.class);
          
                List<String> patterns = jsonPatterns.getPatterns();

                for (String pattern : patterns) {
                    callbacks.printOutput("Proccessed " + pattern + "");

                }
                
                regexPatterns.put(file, patterns);
                
            } catch (Exception e) {
                callbacks.printError("Error loading pattern file " + file + ": " + e.getMessage());
            }
        }
        
        //Headers
        wellKnownHeaders = new ArrayList<String>();
        ClassLoader classLoader = getClass().getClassLoader();
        try (InputStream inputStream = classLoader.getResourceAsStream("headers.json");
                InputStreamReader isr = new InputStreamReader(inputStream);
                BufferedReader reader = new BufferedReader(isr)) {

               String line;
               while ((line = reader.readLine()) != null) {
            	   wellKnownHeaders.add(line.toLowerCase());
               }

           } catch (IOException e) {
               e.printStackTrace();
           }
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        
    	if (! (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY)) {
            return;
        }
    	
    	if (messageIsRequest) {
            // Extract and analyze request parameters
            IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
            List<IParameter> parameters = requestInfo.getParameters();
            for (IParameter parameter : parameters) {
                checkPattern(parameter, messageInfo);
            }
            
            //Process headers
            checkHeaders(messageInfo);
            
        }
    }

    private void checkHeaders(IHttpRequestResponse messageInfo) {
    	
        List<String> headers = helpers.analyzeRequest(messageInfo).getHeaders();
        
    	for (String header : headers) {
            String[] parts = header.split(":", 2);
            if (parts.length == 2) {
            	
                String headerName = parts[0].trim();
                String headerValue = parts[1].trim();
                
                
                //callbacks.printOutput("Header Name: " + headerName + ", Header Value: " + headerValue);
                
                if(! headerName.toLowerCase().startsWith("cookie:") && !(wellKnownHeaders.contains(headerName.toLowerCase()))) {
                
                    printIssue(messageInfo, headerName, "header", "header");
                	
                }
              
            }
        }
    }
    
    
    private void checkPattern(IParameter parameter, IHttpRequestResponse messageInfo) {
    	
        for (String patternKey : regexPatterns.keySet()) {
            for (String pattern : regexPatterns.get(patternKey)) {

            	if(parameter.getType() != IParameter.PARAM_COOKIE) {
            		 if (parameter.getName().toLowerCase().startsWith(pattern.split("=")[0])) {

            			 //callbacks.printOutput("Regex pattern match found: " + pattern + " from" + patternKey +" in parameter " + parameter.getName() + " of type "+ parameter.getType());
                         printIssue(messageInfo, parameter.getName(), patternKey, "parameter");
                     }
            	} else if (! parameter.getName().startsWith("_")){
            		//callbacks.printOutput("Regex pattern match found in cookie: " + pattern + " from" + patternKey +" in parameter " + parameter.getName() + " of type "+ parameter.getType());
                    printIssue(messageInfo, parameter.getName(), patternKey, "cookie");
            	}
               
            }
        }
    }
    
    private void printIssue(IHttpRequestResponse messageInfo, String parameter, String file, String type) {
    	
       
  
    	String url = callbacksHelpers.analyzeRequest(messageInfo).getUrl().toString();
    	if( !(url.contains(".js") || url.contains(".png") || url.contains(".css") || url.contains(".jpg") || url.contains(".jpeg") || url.contains(".js")) ) {
    		
	    	IHttpRequestResponse[] httpMessages = null; 
	    	IHttpService httpService = messageInfo.getHttpService(); 
	
	    	
	    	byte[] request = messageInfo.getRequest();
	    	String requestString = helpers.bytesToString(request);
	    	
	    	int startOffset = requestString.indexOf(parameter);
	    	int endOffset = startOffset + parameter.length();
	    	
	    	List<int[]> requestHighlights = new ArrayList<>();

	    	if (startOffset != -1) { 
	    	    requestHighlights.add(new int[] { startOffset, endOffset });
	    	}
	    	
	    	IScanIssue newIssue = null; 
	    	
	    	if(type == "parameter") {
	    		
	    		String detail = "Found a parameter that might be interesting. \n Found parameter <b> " + parameter + " </b> in "+ callbacksHelpers.analyzeRequest(messageInfo).getUrl().getPath() +" . Test for <b> " + file.split(".json")[0].toUpperCase() + " </b> attacks";
	    		
	    		if(! alreadyReportedParameters.contains(detail)) {
	    			
		    		alreadyReportedParameters.add(detail);
		    		
			    	 newIssue = new CustomScanIssue(
			    		callbacksHelpers.analyzeRequest(messageInfo).getUrl(),
			    	    "[GF] Found interesting parameter",
			    	    "Low",
			    	    "Tentative",
			    	    detail,
			    	    "Test for problem",
			    	    new IHttpRequestResponse[] { callbacks.applyMarkers(messageInfo, requestHighlights, null)},
			    	    httpService,
			    	    detail
			    	);
			    	 callbacks.addScanIssue(newIssue);
	    		}
	    	} else if(type == "cookie") {
	    		
	    		String detail = "Found a cookie parameter that might be interesting. \n Found cookie <b> " + parameter + " </b> ";
	    		
	    		if(! alreadyReportedCookies.contains(detail)) {
	    			 alreadyReportedCookies.add(detail);
			    	 newIssue = new CustomScanIssue(
			    		callbacksHelpers.analyzeRequest(messageInfo).getUrl(),
			    	    "[GF] Found custom cookie parameter",
			    	    "Low",
			    	    "Tentative",
			    	    detail,
			    	    "Test for problem",
			    	    new IHttpRequestResponse[] { callbacks.applyMarkers(messageInfo, requestHighlights, null)},
			    	    httpService,
			    	    detail
			    	);
			    	 callbacks.addScanIssue(newIssue);
	    		}
	    	} else if(type == "header") {
	    		
	    		String detail = "Found a custom header that might be interesting. \n Found header <b> " + parameter + " </b> .";
	    		
	    		if(! alreadyReportedHeaders.contains(detail)) {
	    			 alreadyReportedHeaders.add(detail);
			    	 newIssue = new CustomScanIssue(
			    		callbacksHelpers.analyzeRequest(messageInfo).getUrl(),
			    	    "[GF] Found custom header",
			    	    "Low",
			    	    "Tentative",
			    	    detail,
			    	    "Test for problem",
			    	    new IHttpRequestResponse[] { callbacks.applyMarkers(messageInfo, requestHighlights, null)},
			    	    httpService,
			    	    detail
			    	);
			    	 callbacks.addScanIssue(newIssue);
	    		}
	    	}
	
	    	
	    	// Avoid repeated scan issues
	    	/*boolean found = false;
	    	
	    	for(IScanIssue previousIssue : previousIssues ) {
	    		
	    		String previousDetail = previousIssue.getIssueDetail();
	    		
	    		if(previousDetail != null && previousDetail.equals(newIssue.getIssueDetail())){
	    			callbacks.printOutput("Found this issue previously so lets go out");
	    			found = true;
	    			break;
	    		}
	        }
	    	
	    	if(!found) {
	    		callbacks.addScanIssue(newIssue);
	    	}*/
    	}
    }
}

