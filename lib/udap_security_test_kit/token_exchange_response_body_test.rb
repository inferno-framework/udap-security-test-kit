module UDAPSecurityTestKit
  class TokenExchangeResponseBodyTest < Inferno::Test
    title 'Token exchange response body contains required information encoded in JSON'
    description %(
      The [UDAP JWT-Based Client Authentication Profile, Section 7.1](https://www.udap.org/udap-jwt-client-auth.html)
      states:
      > If the (token exchange) request is approved, the Authorization Server returns a token response as per Section
      5.1 of RFC 6749.

      [RFC 6749 OAuth 2.0 Authorization Framework, Section 5.1](https://datatracker.ietf.org/doc/html/rfc6749#section-5.1)
      lists the `access_token` and `token_type` parameters as REQUIRED.
    )

    id :udap_token_exchange_response_body

    input :token_response_body

    output :udap_access_token,
           :udap_expires_in,
           :udap_received_scopes,
           :udap_refresh_token

    run do
      assert_valid_json(token_response_body)
      token_response_body_parsed = JSON.parse(token_response_body)

      output udap_access_token: token_response_body_parsed['access_token'],
             udap_expires_in: token_response_body_parsed['expires_in'],
             udap_received_scopes: token_response_body_parsed['scope'],
             udap_refresh_token: token_response_body_parsed['refresh_token']

      required_keys = ['access_token', 'token_type']

      required_keys.each do |key|
        assert token_response_body_parsed.key?(key), "Token exchange response does not contain key #{key}"
        assert token_response_body_parsed[key].present?, "Value for key #{key} cannot be empty"
      end
    end
  end
end
