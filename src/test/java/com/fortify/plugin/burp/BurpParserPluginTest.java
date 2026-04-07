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
import static org.mockito.ArgumentMatchers.anyString;
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

    @Test
    public void testParseVulnerabilities() throws Exception {
        InputStream is = getClass().getResourceAsStream("/sample-burp.xml");
        when(scanData.getInputStream(any(Predicate.class))).thenReturn(is);
        when(vulnerabilityHandler.startStaticVulnerability(anyString())).thenReturn(staticVulnerabilityBuilder);
        when(staticVulnerabilityBuilder.setCategory(anyString())).thenReturn(staticVulnerabilityBuilder);
        when(staticVulnerabilityBuilder.setFileName(anyString())).thenReturn(staticVulnerabilityBuilder);
        when(staticVulnerabilityBuilder.setPriority(any(BasicVulnerabilityBuilder.Priority.class))).thenReturn(staticVulnerabilityBuilder);

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
    }

    @Test
    public void testParseVulnerabilitiesWithIssuesTag() throws Exception {
        InputStream is = getClass().getResourceAsStream("/sample-burp-report.xml");
        when(scanData.getInputStream(any(Predicate.class))).thenReturn(is);
        when(vulnerabilityHandler.startStaticVulnerability(anyString())).thenReturn(staticVulnerabilityBuilder);
        when(staticVulnerabilityBuilder.setCategory(anyString())).thenReturn(staticVulnerabilityBuilder);
        when(staticVulnerabilityBuilder.setFileName(anyString())).thenReturn(staticVulnerabilityBuilder);
        when(staticVulnerabilityBuilder.setPriority(any(BasicVulnerabilityBuilder.Priority.class))).thenReturn(staticVulnerabilityBuilder);

        BurpParserPlugin plugin = new BurpParserPlugin();
        plugin.parseVulnerabilities(scanData, vulnerabilityHandler);

        verify(staticVulnerabilityBuilder, times(1)).setCategory(eq("Cross-site scripting (reflected)"));
        verify(staticVulnerabilityBuilder, times(1)).completeVulnerability();
    }

    @Test
    public void testParseVulnerabilitiesWithUppercaseExtension() throws Exception {
        // Mock getInputStream to match .XML
        when(scanData.getInputStream(any(Predicate.class))).thenAnswer(invocation -> {
            Predicate<String> predicate = (Predicate<String>) invocation.getArgument(0);
            if (predicate.test("results.XML")) {
                return getClass().getResourceAsStream("/sample-burp.xml");
            }
            return null;
        });
        when(vulnerabilityHandler.startStaticVulnerability(anyString())).thenReturn(staticVulnerabilityBuilder);
        when(staticVulnerabilityBuilder.setCategory(anyString())).thenReturn(staticVulnerabilityBuilder);
        when(staticVulnerabilityBuilder.setFileName(anyString())).thenReturn(staticVulnerabilityBuilder);
        when(staticVulnerabilityBuilder.setPriority(any(BasicVulnerabilityBuilder.Priority.class))).thenReturn(staticVulnerabilityBuilder);

        BurpParserPlugin plugin = new BurpParserPlugin();
        plugin.parseVulnerabilities(scanData, vulnerabilityHandler);

        verify(staticVulnerabilityBuilder, times(1)).setCategory(eq("Cross-site scripting (reflected)"));
        verify(staticVulnerabilityBuilder, times(1)).completeVulnerability();
    }
}
