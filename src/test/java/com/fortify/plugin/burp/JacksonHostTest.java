package com.fortify.plugin.burp;

import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import org.junit.jupiter.api.Test;

public class JacksonHostTest {
    @Test
    public void testHostWithIpAttribute() throws Exception {
        XmlMapper mapper = new XmlMapper();
        String xml = "<item><host ip=\"127.0.0.1\">http://localhost</host></item>";
        BurpItem item = mapper.readValue(xml, BurpItem.class);
        System.out.println("Host value: " + item.getHost());
        // Depending on Jackson version, it might return empty, throw exception, or return "http://localhost"
    }
}
