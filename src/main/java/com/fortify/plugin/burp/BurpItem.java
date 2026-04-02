package com.fortify.plugin.burp;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class BurpItem {
    private String serialNumber;
    private String type;
    private String name;
    private String host;
    private String path;
    private String location;
    private String severity;
    private String confidence;
    private String issueBackground;
    private String remediationBackground;
    private String issueDetail;
    private String remediationDetail;

    public String getSerialNumber() { return serialNumber; }
    public void setSerialNumber(String serialNumber) { this.serialNumber = serialNumber; }

    public String getType() { return type; }
    public void setType(String type) { this.type = type; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getHost() { return host; }
    public void setHost(String host) { this.host = host; }

    public String getPath() { return path; }
    public void setPath(String path) { this.path = path; }

    public String getLocation() { return location; }
    public void setLocation(String location) { this.location = location; }

    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }

    public String getConfidence() { return confidence; }
    public void setConfidence(String confidence) { this.confidence = confidence; }

    public String getIssueBackground() { return issueBackground; }
    public void setIssueBackground(String issueBackground) { this.issueBackground = issueBackground; }

    public String getRemediationBackground() { return remediationBackground; }
    public void setRemediationBackground(String remediationBackground) { this.remediationBackground = remediationBackground; }

    public String getIssueDetail() { return issueDetail; }
    public void setIssueDetail(String issueDetail) { this.issueDetail = issueDetail; }

    public String getRemediationDetail() { return remediationDetail; }
    public void setRemediationDetail(String remediationDetail) { this.remediationDetail = remediationDetail; }
}
