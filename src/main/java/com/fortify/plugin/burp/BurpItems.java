package com.fortify.plugin.burp;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlRootElement;

import java.util.List;

@JacksonXmlRootElement(localName = "items")
@JsonIgnoreProperties(ignoreUnknown = true)
public class BurpItems {
    @JacksonXmlProperty(isAttribute = true)
    private String burpVersion;
    
    @JacksonXmlProperty(isAttribute = true)
    private String exportTime;

    @JacksonXmlElementWrapper(useWrapping = false)
    @JacksonXmlProperty(localName = "item")
    private List<BurpItem> items;

    public String getBurpVersion() { return burpVersion; }
    public void setBurpVersion(String burpVersion) { this.burpVersion = burpVersion; }

    public String getExportTime() { return exportTime; }
    public void setExportTime(String exportTime) { this.exportTime = exportTime; }

    public List<BurpItem> getItems() { return items; }
    public void setItems(List<BurpItem> items) { this.items = items; }
}
