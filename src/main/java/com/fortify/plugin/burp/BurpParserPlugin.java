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
import java.util.HashSet;
import java.util.Set;

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
            scanBuilder.setEngineVersion(truncate(version != null ? version : "Unknown", 255));
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
                    Set<String> reportedIds = new HashSet<>();
                    for (BurpItem item : burpItems.getItems()) {
                        String uniqueId = generateUniqueId(item);
                        if (reportedIds.add(uniqueId)) {
                            reportIssue(vulnerabilityHandler, item, uniqueId);
                        } else {
                            LOG.debug("Skipping duplicate issue ID in same scan: {}", uniqueId);
                        }
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

    private void reportIssue(VulnerabilityHandler vulnerabilityHandler, BurpItem item, String uniqueId) {
        StaticVulnerabilityBuilder builder = vulnerabilityHandler.startStaticVulnerability(uniqueId);
        
        String name = item.getName() != null ? item.getName() : "Unknown";
        builder.setCategory(truncate(name, 255));
        
        String host = item.getHost() != null ? item.getHost() : "";
        String path = item.getPath() != null ? item.getPath() : "";
        String fileName = host + path;
        if (fileName.isEmpty()) {
            fileName = "Unknown";
        }
        builder.setFileName(truncate(fileName, 255));
        
        builder.setPriority(mapPriority(item.getSeverity()));
        builder.setConfidence(mapConfidence(item.getConfidence()));
        builder.setImpact(mapImpact(item.getSeverity()));
        
        String detail = item.getIssueDetail() != null ? item.getIssueDetail() : name;
        builder.setVulnerabilityAbstract(truncate(detail, 1024));
        
        // Custom attributes
        builder.setStringCustomAttributeValue(BurpVulnerabilityAttribute.ISSUE_NAME, truncate(item.getName(), 255));
        builder.setStringCustomAttributeValue(BurpVulnerabilityAttribute.SEVERITY, truncate(item.getSeverity(), 255));
        builder.setStringCustomAttributeValue(BurpVulnerabilityAttribute.CONFIDENCE, truncate(item.getConfidence(), 255));
        builder.setStringCustomAttributeValue(BurpVulnerabilityAttribute.FULL_FILE_NAME, truncate(host + path, 255));
        builder.setStringCustomAttributeValue(BurpVulnerabilityAttribute.ISSUE_DETAIL, truncate(item.getIssueDetail(), 32000));
        builder.setStringCustomAttributeValue(BurpVulnerabilityAttribute.ISSUE_BACKGROUND, truncate(item.getIssueBackground(), 32000));
        builder.setStringCustomAttributeValue(BurpVulnerabilityAttribute.REMEDIATION_DETAIL, truncate(item.getRemediationDetail(), 32000));
        builder.setStringCustomAttributeValue(BurpVulnerabilityAttribute.REMEDIATION_BACKGROUND,
                truncate(item.getRemediationBackground(), 32000));
        
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

    private String truncate(String value, int length) {
        if (value == null) {
            return null;
        }
        return value.length() > length ? value.substring(0, length) : value;
    }

    private BasicVulnerabilityBuilder.Priority mapPriority(String severity) {
        if (severity == null) {
            return BasicVulnerabilityBuilder.Priority.Low;
        }
        switch (severity.toLowerCase()) {
            case "critical":
                return BasicVulnerabilityBuilder.Priority.Critical;
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

    private float mapConfidence(String confidence) {
        if (confidence == null) return 1.0f;
        switch (confidence.toLowerCase()) {
            case "certain": return 5.0f;
            case "firm": return 3.0f;
            case "tentative": return 1.0f;
            default: return 1.0f;
        }
    }

    private float mapImpact(String severity) {
        if (severity == null) return 1.0f;
        switch (severity.toLowerCase()) {
            case "critical": return 5.0f;
            case "high": return 4.0f;
            case "medium": return 3.0f;
            case "low": return 2.0f;
            case "information": return 1.0f;
            default: return 1.0f;
        }
    }
}
