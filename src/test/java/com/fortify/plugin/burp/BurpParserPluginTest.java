package com.fortify.plugin.burp;

import com.fortify.plugin.api.BasicVulnerabilityBuilder;
import com.fortify.plugin.api.ScanBuilder;
import com.fortify.plugin.api.ScanData;
import com.fortify.plugin.api.StaticVulnerabilityBuilder;
import com.fortify.plugin.api.VulnerabilityHandler;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.InputStream;
import java.util.function.Predicate;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyFloat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class BurpParserPluginTest {

    @Mock
    private ScanData scanData;

    @Mock
    private VulnerabilityHandler vulnerabilityHandler;

    @Mock
    private StaticVulnerabilityBuilder staticVulnerabilityBuilder;

    @Mock
    private ScanBuilder scanBuilder;

    private void setupMocks() {
        when(vulnerabilityHandler.startStaticVulnerability(anyString())).thenReturn(staticVulnerabilityBuilder);
        when(staticVulnerabilityBuilder.setCategory(anyString())).thenReturn(staticVulnerabilityBuilder);
        when(staticVulnerabilityBuilder.setFileName(anyString())).thenReturn(staticVulnerabilityBuilder);
        when(staticVulnerabilityBuilder.setPriority(any(BasicVulnerabilityBuilder.Priority.class))).thenReturn(staticVulnerabilityBuilder);
        when(staticVulnerabilityBuilder.setConfidence(anyFloat())).thenReturn(staticVulnerabilityBuilder);
        when(staticVulnerabilityBuilder.setImpact(anyFloat())).thenReturn(staticVulnerabilityBuilder);
        when(staticVulnerabilityBuilder.setVulnerabilityAbstract(anyString())).thenReturn(staticVulnerabilityBuilder);
    }

    @Test
    public void testParseVulnerabilities() throws Exception {
        InputStream is = getClass().getResourceAsStream("/sample-burp.xml");
        when(scanData.getInputStream(any(Predicate.class))).thenReturn(is);
        setupMocks();

        BurpParserPlugin plugin = new BurpParserPlugin();
        plugin.parseVulnerabilities(scanData, vulnerabilityHandler);

        verify(staticVulnerabilityBuilder, times(1)).setCategory(eq("Cross-site scripting (reflected)"));
        verify(staticVulnerabilityBuilder, times(1)).setPriority(eq(BasicVulnerabilityBuilder.Priority.High));
        verify(staticVulnerabilityBuilder, times(1)).setFileName(eq("http://localhost/vulnerable.php"));
        verify(staticVulnerabilityBuilder, times(1)).completeVulnerability();
    }

    @Test
    public void testParseScan() throws Exception {
        InputStream is = getClass().getResourceAsStream("/sample-burp.xml");
        when(scanData.getInputStream(any(Predicate.class))).thenReturn(is);

        BurpParserPlugin plugin = new BurpParserPlugin();
        plugin.parseScan(scanData, scanBuilder);

        verify(scanBuilder, times(1)).setEngineVersion(eq("2023.10.1"));
        verify(scanBuilder, times(1)).setScanDate(any());
        verify(scanBuilder, times(1)).completeScan();
    }

    @Test
    public void testParseVulnerabilitiesWithIssuesTag() throws Exception {
        InputStream is = getClass().getResourceAsStream("/sample-burp-report.xml");
        when(scanData.getInputStream(any(Predicate.class))).thenReturn(is);
        setupMocks();

        BurpParserPlugin plugin = new BurpParserPlugin();
        plugin.parseVulnerabilities(scanData, vulnerabilityHandler);

        verify(staticVulnerabilityBuilder, times(1)).setCategory(eq("Cross-site scripting (reflected)"));
        verify(staticVulnerabilityBuilder, times(1)).completeVulnerability();
    }

    @Test
    public void testParseSnippetWithCDataAndAttributes() throws Exception {
        String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                "<issues burpVersion=\"2025.12.4\">" +
                "  <issue>" +
                "    <serialNumber>2582756949112998912</serialNumber>" +
                "    <name><![CDATA[Strict transport security not enforced]]></name>" +
                "    <host ip=\"10.150.39.155\">https://mes-edi-portal-tradingpartner-management-int.apps.psponcltr01.int.praws.hicloud</host>" +
                "    <path><![CDATA[/EDI_Portal/admin/search]]></path>" +
                "    <severity>Low</severity>" +
                "    <confidence>Certain</confidence>" +
                "  </issue>" +
                "</issues>";
        
        when(scanData.getInputStream(any(Predicate.class))).thenReturn(new java.io.ByteArrayInputStream(xml.getBytes()));
        setupMocks();

        BurpParserPlugin plugin = new BurpParserPlugin();
        plugin.parseVulnerabilities(scanData, vulnerabilityHandler);

        verify(staticVulnerabilityBuilder, times(1)).setCategory(eq("Strict transport security not enforced"));
        verify(staticVulnerabilityBuilder, times(1)).setFileName(contains("https://mes-edi-portal"));
        verify(staticVulnerabilityBuilder, times(1)).completeVulnerability();
    }
}
