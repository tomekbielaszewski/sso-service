package org.grizz.config.security;

import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.stereotype.Component;

import javax.servlet.Filter;

@Component
public class OAuth2FilterFactory {

    public Filter create(String url,
                               AuthorizationCodeResourceDetails resourceDetails,
                               OAuth2ClientContext oAuth2ClientContext,
                               ResourceServerProperties resourceServerProperties,
                               ApplicationEventPublisher eventPublisher) {
        OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter(url);
        OAuth2RestTemplate oAuth2RestTemplate = new OAuth2RestTemplate(resourceDetails, oAuth2ClientContext);
        filter.setRestTemplate(oAuth2RestTemplate);
        UserInfoTokenServices tokenServices = new UserInfoTokenServices(resourceServerProperties.getUserInfoUri(), resourceDetails.getClientId());
        tokenServices.setRestTemplate(oAuth2RestTemplate);
        filter.setTokenServices(tokenServices);
        filter.setApplicationEventPublisher(eventPublisher);
        return filter;
    }
}
