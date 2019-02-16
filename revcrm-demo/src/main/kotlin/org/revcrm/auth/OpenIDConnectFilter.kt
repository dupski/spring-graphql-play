package org.revcrm.auth

import com.auth0.jwk.UrlJwkProvider
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.jwt.JwtHelper
import org.springframework.security.jwt.crypto.sign.RsaVerifier
import org.springframework.security.oauth2.client.OAuth2RestTemplate
import org.springframework.security.oauth2.common.OAuth2AccessToken
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
import java.net.URL
import java.security.interfaces.RSAPublicKey
import java.util.*
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.springframework.security.authentication.AuthenticationManager



class OpenIDConnectFilter : AbstractAuthenticationProcessingFilter("/login") {

    var restTemplate: OAuth2RestTemplate? = null

    init {
        authenticationManager = NoopAuthenticationManager()
    }

    override fun attemptAuthentication(
            request: HttpServletRequest, response: HttpServletResponse): Authentication {
        val accessToken: OAuth2AccessToken
        try {
            accessToken = restTemplate!!.getAccessToken()
        } catch (e: OAuth2Exception) {
            throw BadCredentialsException("Could not obtain access token", e)
        }

        try {
            val idToken = accessToken.additionalInformation["id_token"].toString()
            val kid = JwtHelper.headers(idToken).get("kid")!!
            val tokenDecoded = JwtHelper.decodeAndVerify(idToken, verifier(kid))
            val authInfo = ObjectMapper()
                    .readValue(tokenDecoded.getClaims(), Map::class.java) as Map<String, String>
            verifyClaims(authInfo)
            val user = buildUser(authInfo, accessToken)
            return UsernamePasswordAuthenticationToken(user, null, user.getAuthorities())
        } catch (e: InvalidTokenException) {
            throw BadCredentialsException("Could not obtain user details from token", e)
        }
    }

    private fun buildUser(authInfo: Map<String, String>, token: OAuth2AccessToken): UserDetails {
        val userId = authInfo.get("sub");
        val email = authInfo.get("email");
        // TODO: Add Roles, etc
        return User.withUsername(email).build()
    }

    @Value("\${openid.clientId}")
    private val clientId: String? = null

    @Value("\${openid.jwksUri}")
    private val jwksUrl: String? = null

    @Value("\${openid.issuer}")
    private val issuer: String? = null

    private fun verifier(kid: String): RsaVerifier {
        val provider = UrlJwkProvider(URL(jwksUrl))
        val jwk = provider.get(kid)
        return RsaVerifier(jwk.getPublicKey() as RSAPublicKey)
    }

    fun verifyClaims(claims: Map<*, *>) {
        val exp = claims["exp"] as Int
        val expireDate = Date(exp * 1000L)
        val now = Date()
        if (expireDate.before(now) || claims["iss"] != issuer ||
                claims["aud"] != clientId) {
            throw RuntimeException("Invalid claims")
        }
    }

    private class NoopAuthenticationManager : AuthenticationManager {
        override fun authenticate(authentication: Authentication): Authentication {
            throw UnsupportedOperationException("No authentication should be done with this AuthenticationManager")
        }
    }
}