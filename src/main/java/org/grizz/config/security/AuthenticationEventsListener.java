package org.grizz.config.security;

import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.oauth2.client.filter.OAuth2AuthenticationFailureEvent;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationEventsListener {

    @EventListener
    public void handleOAuth2AuthenticationFailureEvent(OAuth2AuthenticationFailureEvent event) {
        System.out.println(event.getAuthentication());
        System.out.println(event.getException());
    }

    @EventListener
    public void handleAuthenticationSuccessEvent(AuthenticationSuccessEvent event) {
        System.out.println(event.getAuthentication());
    }
}
