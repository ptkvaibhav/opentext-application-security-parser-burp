package com.fortify.plugin.burp;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlRootElement;

import java.util.List;

/**
 * Represents the root element of a Burp Suite XML export.
 * Handles both '&lt;items&gt;' and '&lt;issues&gt;' root tags using Jackson annotations.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@JacksonXmlRootElement(localName = "issues")
public class BurpItems {
    @JacksonXmlProperty(isAttribute = true)
    private String burpVersion;
    
    @JacksonXmlProperty(isAttribute = true)
    private String exportTime;

    @JacksonXmlElementWrapper(useWrapping = false)
    @JacksonXmlProperty(localName = "issue")
    @JsonAlias({"item", "issue"})
    private List<BurpItem> items;

    public String getBurpVersion() {
        return burpVersion;
    }

    public void setBurpVersion(String burpVersion) {
        this.burpVersion = burpVersion;
    }

    public String getExportTime() {
        return exportTime;
    }

    public void setExportTime(String exportTime) {
        this.exportTime = exportTime;
    }

    public List<BurpItem> getItems() {
        return items;
    }

    public void setItems(List<BurpItem> items) {
        this.items = items;
    }
}
