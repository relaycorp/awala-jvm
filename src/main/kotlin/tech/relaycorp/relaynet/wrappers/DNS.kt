package tech.relaycorp.relaynet.wrappers

import java.util.regex.Pattern

internal object DNS {
    // Taken from https://owasp.org/www-community/OWASP_Validation_Regex_Repository
    private val domainNameRegex =
        Pattern.compile(
            "^([a-z0-9]([a-z0-9\\-]{0,61}[a-z0-9])?\\.)+(xn--[a-z0-9-]{2,24}|[a-z]{2,24})\$",
            Pattern.CASE_INSENSITIVE,
        )

    /**
     * Report whether [domainName] is a syntactically-valid domain name.
     *
     * No actual DNS lookup is done.
     */
    fun isValidDomainName(domainName: String): Boolean =
        domainNameRegex.matcher(domainName).matches()
}
