package org.owasp.html;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import com.code_intelligence.jazzer.junit.FuzzTest;

class MyFuzzTest2 {

    @FuzzTest
    void myFuzzTest(FuzzedDataProvider data) {
        PolicyFactory policy = Sanitizers.FORMATTING.and(Sanitizers.LINKS);
        String fuzzData = data.consumeString(1000);
        String safeString = policy.sanitize(fuzzData);

        assert !safeString.contains("rel=nofollow") : new FuzzerSecurityIssueHigh("There is an XSS regarding script!");
    }
}