package com.fortify.plugin.burp;

import com.fortify.plugin.api.IssueBuilder;
import com.fortify.plugin.api.ScanData;
import com.fortify.plugin.api.VulnerabilityPriority;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.InputStream;
import java.util.function.Predicate;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class BurpIssueParserTest {

    @Mock
    private ScanData scanData;

    @Mock
    private IssueBuilder issueBuilder;

    @Test
    public void testParse() throws Exception {
        InputStream is = getClass().getResourceAsStream("/sample-burp.xml");
        when(scanData.getInputStream(any(Predicate.class))).thenReturn(is);

        BurpIssueParser parser = new BurpIssueParser();
        parser.parse(scanData, issueBuilder);

        verify(issueBuilder, times(1)).setCategory(eq("Cross-site scripting (reflected)"));
        verify(issueBuilder, times(1)).setPriority(eq(VulnerabilityPriority.High));
        verify(issueBuilder, times(1)).setAttribute(eq(BurpVulnerabilityAttribute.SEVERITY), eq("High"));
        verify(issueBuilder, times(1)).completeIssue();
    }
}
