package org.revcrm.auth

import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.oauth2.client.OAuth2ClientContext
import org.springframework.security.oauth2.client.OAuth2RestTemplate
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client

@Configuration
@EnableOAuth2Client
class OpenIDConfiguration {

    @Value("\${openid.clientId}")
    private val clientId: String? = null

    @Value("\${openid.clientSecret}")
    private val clientSecret: String? = null

    @Value("\${openid.accessTokenUri}")
    private val accessTokenUri: String? = null

    @Value("\${openid.userAuthorizationUri}")
    private val userAuthorizationUri: String? = null

    @Value("\${openid.redirectUri}")
    private val redirectUri: String? = null

    @Bean
    fun openIdConfig(): OAuth2ProtectedResourceDetails {
        val details = AuthorizationCodeResourceDetails()
        details.clientId = clientId
        details.clientSecret = clientSecret
        details.accessTokenUri = accessTokenUri
        details.userAuthorizationUri = userAuthorizationUri
        details.scope = listOf("openid", "email")
        details.preEstablishedRedirectUri = redirectUri
        details.isUseCurrentUri = false
        return details
    }

    @Bean
    fun openIdRestTemplate(clientContext: OAuth2ClientContext): OAuth2RestTemplate {
        return OAuth2RestTemplate(openIdConfig(), clientContext)
    }
}