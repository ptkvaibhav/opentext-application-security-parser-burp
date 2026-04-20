package com.fortify.plugin.burp;

import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class JacksonHostTest {
    @Test
    public void testHostWithIpAttribute() throws Exception {
        XmlMapper mapper = new XmlMapper();
        String xml = "<item><host ip=\"127.0.0.1\">http://localhost</host></item>";
        BurpItem item = mapper.readValue(xml, BurpItem.class);
        assertEquals("http://localhost", item.getHost(), "Host should be http://localhost");
    }

    @Test
    public void testItemsRoot() throws Exception {
        XmlMapper mapper = new XmlMapper();
        String xml = "<items burpVersion=\"2023.10.1\"><item><name>Test</name></item></items>";
        BurpItems items = mapper.readValue(xml, BurpItems.class);
        assertNotNull(items);
        assertEquals("2023.10.1", items.getBurpVersion());
        assertNotNull(items.getItems());
        assertEquals(1, items.getItems().size());
    }

    @Test
    public void testMultipleIssues() throws Exception {
        XmlMapper mapper = new XmlMapper();
        String xml = "<issues burpVersion=\"2023.10.1\">" +
                     "<issue><name>Test 1</name></issue>" +
                     "<issue><name>Test 2</name></issue>" +
                     "</issues>";
        BurpItems items = mapper.readValue(xml, BurpItems.class);
        assertNotNull(items);
        assertNotNull(items.getItems());
        assertEquals(2, items.getItems().size());
        assertEquals("Test 1", items.getItems().get(0).getName());
        assertEquals("Test 2", items.getItems().get(1).getName());
    }
}
