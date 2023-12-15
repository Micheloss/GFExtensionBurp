package com.burpextensor.gfextension.pojo;

import burp.*;

import java.net.URL;

public class CustomScanIssue implements IScanIssue {
	
    private URL url;
    private String issueName;
    private String severity;
    private String confidence;
    private String issueBackground;
    private String remediationBackground;
    private IHttpRequestResponse[] httpMessages;
    private IHttpService httpService;
    private String detail;

    public CustomScanIssue(URL url, String issueName, String severity, String confidence, String issueBackground, String remediationBackground, IHttpRequestResponse[] httpMessages, IHttpService httpService, String detail) {
        this.url = url;
        this.issueName = issueName;
        this.severity = severity;
        this.confidence = confidence;
        this.issueBackground = issueBackground;
        this.remediationBackground = remediationBackground;
        this.httpMessages = httpMessages;
        this.httpService = httpService;
        this.detail = detail;
    }

    @Override
    public URL getUrl() {
        return url;
    }

    @Override
    public String getIssueName() {
        return issueName;
    }

    @Override
    public int getIssueType() {
        return 0; // Cambiar según el tipo de problema
    }

    @Override
    public String getSeverity() {
        return severity;
    }

    @Override
    public String getConfidence() {
        return confidence;
    }

    @Override
    public String getIssueBackground() {
        return issueBackground;
    }

    @Override
    public String getRemediationBackground() {
        return remediationBackground;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }

    @Override
    public String getIssueDetail() {
      return detail;
    }

    @Override
    public String getRemediationDetail() {
      return null;
    }
}
