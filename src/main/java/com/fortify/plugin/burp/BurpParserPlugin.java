package com.fortify.plugin.burp;

import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import com.fortify.plugin.api.BasicVulnerabilityBuilder;
import com.fortify.plugin.api.ScanBuilder;
import com.fortify.plugin.api.ScanData;
import com.fortify.plugin.api.ScanParsingException;
import com.fortify.plugin.api.StaticVulnerabilityBuilder;
import com.fortify.plugin.api.VulnerabilityHandler;
import com.fortify.plugin.spi.ParserPlugin;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

public class BurpParserPlugin implements ParserPlugin<BurpVulnerabilityAttribute> {

    private final XmlMapper xmlMapper = new XmlMapper();

    @Override
    public Class<BurpVulnerabilityAttribute> getVulnerabilityAttributesClass() {
        return BurpVulnerabilityAttribute.class;
    }

    @Override
    public void parseScan(ScanData scanData, ScanBuilder scanBuilder) throws ScanParsingException, IOException {
        try (InputStream is = scanData.getInputStream(name -> name.toLowerCase().endsWith(".xml"))) {
            if (is == null) {
                throw new ScanParsingException("No Burp XML file found in the uploaded artifact.");
            }
            BurpItems burpItems = xmlMapper.readValue(is, BurpItems.class);
            if (burpItems == null) {
                 throw new ScanParsingException("Failed to parse Burp XML file.");
            }
            scanBuilder.setEngineVersion(burpItems.getBurpVersion());
            scanBuilder.setScanDate(new Date());
            scanBuilder.completeScan();
        }
    }

    @Override
    public void parseVulnerabilities(ScanData scanData, VulnerabilityHandler vulnerabilityHandler)
            throws ScanParsingException, IOException {
        try (InputStream is = scanData.getInputStream(name -> name.toLowerCase().endsWith(".xml"))) {
            if (is != null) {
                BurpItems burpItems = xmlMapper.readValue(is, BurpItems.class);
                if (burpItems != null && burpItems.getItems() != null) {
                    for (BurpItem item : burpItems.getItems()) {
                        reportIssue(vulnerabilityHandler, item);
                    }
                }
            }
        }
    }

    private void reportIssue(VulnerabilityHandler vulnerabilityHandler, BurpItem item) {
        StaticVulnerabilityBuilder builder = vulnerabilityHandler.startStaticVulnerability(generateUniqueId(item));
        
        builder.setCategory(item.getName() != null ? item.getName() : "Unknown");
        String host = item.getHost() != null ? item.getHost() : "";
        String path = item.getPath() != null ? item.getPath() : "";
        String fileName = host + path;
        if (fileName.isEmpty()) {
            fileName = "Unknown";
        } else if (fileName.length() > 255) {
            fileName = fileName.substring(0, 255);
        }
        builder.setFileName(fileName);
        builder.setPriority(mapPriority(item.getSeverity()));
        
        // Custom attributes
        builder.setStringCustomAttributeValue(BurpVulnerabilityAttribute.ISSUE_NAME, item.getName());
        builder.setStringCustomAttributeValue(BurpVulnerabilityAttribute.SEVERITY, item.getSeverity());
        builder.setStringCustomAttributeValue(BurpVulnerabilityAttribute.CONFIDENCE, item.getConfidence());
        builder.setStringCustomAttributeValue(BurpVulnerabilityAttribute.FULL_FILE_NAME, host + path);
        builder.setStringCustomAttributeValue(BurpVulnerabilityAttribute.ISSUE_DETAIL, item.getIssueDetail());
        builder.setStringCustomAttributeValue(BurpVulnerabilityAttribute.ISSUE_BACKGROUND, item.getIssueBackground());
        builder.setStringCustomAttributeValue(BurpVulnerabilityAttribute.REMEDIATION_DETAIL, item.getRemediationDetail());
        builder.setStringCustomAttributeValue(BurpVulnerabilityAttribute.REMEDIATION_BACKGROUND,
                item.getRemediationBackground());
        
        builder.completeVulnerability();
    }

    private String generateUniqueId(BurpItem item) {
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            String combined = item.getName() + "|" + item.getHost() + "|" + item.getPath() + "|" + item.getLocation();
            byte[] hash = digest.digest(combined.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder(2 * hash.length);
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            return item.getSerialNumber() != null ? item.getSerialNumber() : "00000000000000000000000000000000";
        }
    }

    private BasicVulnerabilityBuilder.Priority mapPriority(String severity) {
        if (severity == null) {
            return BasicVulnerabilityBuilder.Priority.Low;
        }
        switch (severity.toLowerCase()) {
            case "high":
                return BasicVulnerabilityBuilder.Priority.High;
            case "medium":
                return BasicVulnerabilityBuilder.Priority.Medium;
            case "low":
            case "information":
            default:
                return BasicVulnerabilityBuilder.Priority.Low;
        }
    }
}
