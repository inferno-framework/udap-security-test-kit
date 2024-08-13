module UDAPSecurityTestKit
  class TokenExchangeResponseHeadersTest < Inferno::Test
    title 'Response includes correct HTTP Cache-Control and Pragma headers'
    description %(
      [RFC 6749 OAuth 2.0 Authorization Framework Section 5.1](https://datatracker.ietf.org/doc/html/rfc6749#section-5.1)
      states the following:
      > The authorization server MUST include the HTTP "Cache-Control" response
        header field with a value of
      > "no-store" in any response containing tokens, credentials, or other
        sensitive information, as well as the "Pragma" response header field with a value of "no-cache".
    )
    id :udap_token_exchange_response_headers

    uses_request :token_exchange

    run do
      skip_if request.status != 200, 'Token exchange was unsuccessful'

      cc_header = request.response_header('Cache-Control')&.value

      assert cc_header&.downcase&.include?('no-store'),
             'Token response must have `Cache-Control` header containing `no-store`.'

      pragma_header = request.response_header('Pragma')&.value

      assert pragma_header&.downcase&.include?('no-cache'),
             'Token response must have `Pragma` header containing `no-cache`.'
    end
  end
end
