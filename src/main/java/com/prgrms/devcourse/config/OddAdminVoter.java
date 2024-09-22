package com.prgrms.devcourse.config;

import static org.apache.commons.lang3.math.NumberUtils.toInt;

import java.util.Collection;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.servlet.http.HttpServletRequest;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class OddAdminVoter implements AccessDecisionVoter<FilterInvocation> {

    static final Pattern PATTERN = Pattern.compile("[0-9]+$");

    private final RequestMatcher requestMatcher;

    public OddAdminVoter(RequestMatcher requestMatcher) {
        this.requestMatcher = requestMatcher;
    }

    @Override
    public boolean supports(ConfigAttribute configAttribute) {
        return true;
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return FilterInvocation.class.isAssignableFrom(aClass);
    }

    @Override
    public int vote(Authentication authentication, FilterInvocation filterInvocation,
                    Collection<ConfigAttribute> collection) {

        /*
        URL 이 "/admin" 이 아니면 승인 처리
        이유 -> "/admin" 이 아닌 URL 은 일반 사용자들에게 열려 있는 경로일 수 있기 때문이다.
            -> 만약 접근을 제한시킨다면, "/admin" 경로가 아닌 다른 경로들은 접근할 수 없다.
        */
        HttpServletRequest request = filterInvocation.getRequest();
        if (!requiresAuthorization(request)) {
            return ACCESS_GRANTED;
        }

        User user = (User) authentication.getPrincipal();
        String username = user.getUsername();

        Matcher matcher = PATTERN.matcher(username);
        if (matcher.find()) {
            int number = toInt(matcher.group(), 0);
            if (number % 2 == 1) return ACCESS_GRANTED;
        }
        return ACCESS_DENIED;
    }

    private boolean requiresAuthorization(HttpServletRequest request) {
        return requestMatcher.matches(request);
    }
}
