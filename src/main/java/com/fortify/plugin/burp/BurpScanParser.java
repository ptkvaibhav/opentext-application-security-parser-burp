package com.fortify.plugin.burp;

import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import com.fortify.plugin.api.ScanBuilder;
import com.fortify.plugin.api.ScanData;
import com.fortify.plugin.spi.ScanParser;

import java.io.IOException;
import java.io.InputStream;
import java.util.Date;

public class BurpScanParser implements ScanParser {

    @Override
    public void parse(ScanData scanData, ScanBuilder scanBuilder) throws IOException {
        try (InputStream is = scanData.getInputStream(name -> name.endsWith(".xml"))) {
            if (is != null) {
                XmlMapper xmlMapper = new XmlMapper();
                BurpItems burpItems = xmlMapper.readValue(is, BurpItems.class);
                
                scanBuilder.setEngineVersion(burpItems.getBurpVersion());
                // Burp exports don't always have a clear scan date in the items, 
                // but we can use exportTime if available.
                // For simplicity, we use current date if parsing fails.
                scanBuilder.setScanDate(new Date());
            }
        }
    }
}
