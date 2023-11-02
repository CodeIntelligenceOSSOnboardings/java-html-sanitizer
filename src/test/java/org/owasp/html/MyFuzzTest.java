package org.owasp.html;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import com.code_intelligence.jazzer.junit.FuzzTest;

class MyFuzzTest {
    @FuzzTest
    void myFuzzTest1(FuzzedDataProvider data) {

        PolicyFactory policy = new HtmlPolicyBuilder()
                .allowCommonBlockElements()
                .allowElements("option", "select")
                .disallowElements("script")
                .toFactory();

        String input = data.consumeString(10000);
        String safeOutput = policy.sanitize(input);

        assert !safeOutput.contains("</script") : new FuzzerSecurityIssueHigh("There is an XSS regarding script!");
    }

}
