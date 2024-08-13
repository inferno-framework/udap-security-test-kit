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

    run do
      assert_valid_json(token_response_body)
      token_response_body_parsed = JSON.parse(token_response_body)

      required_keys = ['access_token', 'token_type']

      required_keys.each do |key|
        assert token_response_body_parsed.key?(key), "Token exchange response does not contain key #{key}"
        assert token_response_body_parsed[key].present?, "Value for key #{key} cannot be empty"
      end
    end
  end
end
