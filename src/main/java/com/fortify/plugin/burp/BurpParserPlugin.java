package com.fortify.plugin.burp;

import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import com.fortify.plugin.api.BasicVulnerabilityBuilder;
import com.fortify.plugin.api.ScanBuilder;
import com.fortify.plugin.api.ScanData;
import com.fortify.plugin.api.ScanParsingException;
import com.fortify.plugin.api.StaticVulnerabilityBuilder;
import com.fortify.plugin.api.VulnerabilityHandler;
import com.fortify.plugin.spi.ParserPlugin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

public class BurpParserPlugin implements ParserPlugin<BurpVulnerabilityAttribute> {
    private static final Logger LOG = LoggerFactory.getLogger(BurpParserPlugin.class);
    private final XmlMapper xmlMapper = new XmlMapper();

    @Override
    public void start() throws Exception {
        LOG.info("Burp Suite Parser Plugin is starting");
    }

    @Override
    public void stop() throws Exception {
        LOG.info("Burp Suite Parser Plugin is stopping");
    }

    @Override
    public Class<BurpVulnerabilityAttribute> getVulnerabilityAttributesClass() {
        return BurpVulnerabilityAttribute.class;
    }

    @Override
    public void parseScan(ScanData scanData, ScanBuilder scanBuilder) throws ScanParsingException, IOException {
        LOG.info("Parsing scan data for session: {}", scanData.getSessionId());
        try (InputStream is = scanData.getInputStream(name -> name.toLowerCase().endsWith(".xml"))) {
            if (is == null) {
                LOG.error("No Burp XML file found in the uploaded artifact for session: {}", scanData.getSessionId());
                throw new ScanParsingException("No Burp XML file found in the uploaded artifact.");
            }
            BurpItems burpItems = xmlMapper.readValue(is, BurpItems.class);
            if (burpItems == null) {
                LOG.error("Failed to parse Burp XML file for session: {}", scanData.getSessionId());
                throw new ScanParsingException("Failed to parse Burp XML file.");
            }
            String version = burpItems.getBurpVersion();
            LOG.info("Detected Burp version: {}", version);
            scanBuilder.setEngineVersion(version != null ? version : "Unknown");
            scanBuilder.setScanDate(new Date());
            scanBuilder.completeScan();
        } catch (Exception e) {
            LOG.error("Error parsing scan: " + e.getMessage(), e);
            throw e;
        }
    }

    @Override
    public void parseVulnerabilities(ScanData scanData, VulnerabilityHandler vulnerabilityHandler)
            throws ScanParsingException, IOException {
        LOG.info("Parsing vulnerabilities for session: {}", scanData.getSessionId());
        try (InputStream is = scanData.getInputStream(name -> name.toLowerCase().endsWith(".xml"))) {
            if (is != null) {
                BurpItems burpItems = xmlMapper.readValue(is, BurpItems.class);
                if (burpItems != null && burpItems.getItems() != null) {
                    LOG.info("Found {} issues in Burp XML", burpItems.getItems().size());
                    for (BurpItem item : burpItems.getItems()) {
                        reportIssue(vulnerabilityHandler, item);
                    }
                } else {
                    LOG.warn("No issues found in Burp XML or failed to parse items");
                }
            } else {
                LOG.error("No Burp XML file found during vulnerability parsing for session: {}", scanData.getSessionId());
            }
        } catch (Exception e) {
            LOG.error("Error parsing vulnerabilities: " + e.getMessage(), e);
            throw e;
        }
    }

    private void reportIssue(VulnerabilityHandler vulnerabilityHandler, BurpItem item) {
        String uniqueId = generateUniqueId(item);
        StaticVulnerabilityBuilder builder = vulnerabilityHandler.startStaticVulnerability(uniqueId);
        
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
            String name = item.getName() != null ? item.getName() : "";
            String host = item.getHost() != null ? item.getHost() : "";
            String path = item.getPath() != null ? item.getPath() : "";
            String location = item.getLocation() != null ? item.getLocation() : "";
            
            String combined = name + "|" + host + "|" + path + "|" + location;
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
            LOG.warn("MD5 not available, falling back to serial number for ID");
            return item.getSerialNumber() != null ? item.getSerialNumber() : 
                String.valueOf(System.identityHashCode(item));
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
