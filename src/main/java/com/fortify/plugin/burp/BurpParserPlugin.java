package com.fortify.plugin.burp;

import com.fortify.plugin.spi.IssueParser;
import com.fortify.plugin.spi.ParserPlugin;
import com.fortify.plugin.spi.ScanParser;
import com.fortify.plugin.spi.VulnerabilityAttribute;

import java.util.Arrays;
import java.util.List;

public class BurpParserPlugin implements ParserPlugin {

    @Override
    public ScanParser getScanParser() {
        return new BurpScanParser();
    }

    @Override
    public IssueParser getIssueParser() {
        return new BurpIssueParser();
    }

    @Override
    public List<VulnerabilityAttribute> getVulnerabilityAttributes() {
        return Arrays.asList(BurpVulnerabilityAttribute.values());
    }
}
