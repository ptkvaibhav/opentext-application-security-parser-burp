package com.fortify.plugin.burp;

import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import com.fortify.plugin.api.IssueBuilder;
import com.fortify.plugin.api.ScanData;
import com.fortify.plugin.api.VulnerabilityPriority;
import com.fortify.plugin.spi.IssueParser;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class BurpIssueParser implements IssueParser {

    @Override
    public void parse(ScanData scanData, IssueBuilder issueBuilder) throws IOException {
        try (InputStream is = scanData.getInputStream(name -> name.endsWith(".xml"))) {
            if (is != null) {
                XmlMapper xmlMapper = new XmlMapper();
                BurpItems burpItems = xmlMapper.readValue(is, BurpItems.class);
                
                if (burpItems.getItems() != null) {
                    for (BurpItem item : burpItems.getItems()) {
                        reportIssue(issueBuilder, item);
                    }
                }
            }
        }
    }

    private void reportIssue(IssueBuilder issueBuilder, BurpItem item) {
        issueBuilder.setUniqueId(generateUniqueId(item));
        issueBuilder.setCategory(item.getName());
        issueBuilder.setFileName(item.getHost() + item.getPath());
        issueBuilder.setPriority(mapPriority(item.getSeverity()));
        
        // Custom attributes
        issueBuilder.setAttribute(BurpVulnerabilityAttribute.ISSUE_NAME, item.getName());
        issueBuilder.setAttribute(BurpVulnerabilityAttribute.SEVERITY, item.getSeverity());
        issueBuilder.setAttribute(BurpVulnerabilityAttribute.CONFIDENCE, item.getConfidence());
        issueBuilder.setAttribute(BurpVulnerabilityAttribute.FULL_FILE_NAME, item.getHost() + item.getPath());
        issueBuilder.setAttribute(BurpVulnerabilityAttribute.ISSUE_DETAIL, item.getIssueDetail());
        issueBuilder.setAttribute(BurpVulnerabilityAttribute.ISSUE_BACKGROUND, item.getIssueBackground());
        issueBuilder.setAttribute(BurpVulnerabilityAttribute.REMEDIATION_DETAIL, item.getRemediationDetail());
        issueBuilder.setAttribute(BurpVulnerabilityAttribute.REMEDIATION_BACKGROUND, item.getRemediationBackground());
        
        issueBuilder.completeIssue();
    }

    private String generateUniqueId(BurpItem item) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String combined = item.getName() + "|" + item.getHost() + "|" + item.getPath() + "|" + item.getLocation();
            byte[] hash = digest.digest(combined.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            return item.getSerialNumber(); // Fallback
        }
    }

    private VulnerabilityPriority mapPriority(String severity) {
        if (severity == null) return VulnerabilityPriority.Low;
        switch (severity.toLowerCase()) {
            case "high": return VulnerabilityPriority.High;
            case "medium": return VulnerabilityPriority.Medium;
            case "low": return VulnerabilityPriority.Low;
            case "information": return VulnerabilityPriority.Low;
            default: return VulnerabilityPriority.Low;
        }
    }
}
