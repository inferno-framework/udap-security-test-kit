require_relative 'udap_client_assertion_payload_builder'

module UDAPSecurityTestKit
  class AuthorizationCodeTokenExchangeTest < Inferno::Test
    title 'OAuth token exchange request succeeds when supplied correct information'
    description %(
      The [UDAP Security IG Section 4.2 on Obtaining an Access Token](https://hl7.org/fhir/us/udap-security/STU1/consumer.html#obtaining-an-access-token)
      states the following:
      - Client applications SHALL exchange authorization codes for access
        tokens as per Section 4.1.3 of RFC 6749
      - Client applications authenticating with a private key and
        Authentication Token ... SHALL submit a POST request to the Authorization Server’s token endpoint
      - An Authorization Server receiving token requests containing
        Authentication Tokens as above SHALL validate and respond to the request, as per Sections 6 and 7 of [UDAP
        JWT-Based Client Authentication](https://www.udap.org/udap-jwt-client-auth.html).
    )
    id :udap_authorization_code_token_exchange

    input :udap_authorization_code,
          :udap_client_id

    input :udap_token_endpoint,
          title: 'Token Endpoint',
          description: 'The full URL from which Inferno will request an access token'

    input :udap_auth_code_flow_client_cert_pem,
          title: 'X.509 Client Certificate (PEM Format)',
          type: 'textarea',
          description: %(
            A list of one or more X.509 certificates in PEM format separated by a newline.
            The first (leaf) certificate MUST
            represent the client entity Inferno registered as,
            and the trust chain that will be built from the provided certificate(s) must resolve to a CA trusted by the
            authorization server under test.
          )

    input :udap_auth_code_flow_client_private_key,
          type: 'textarea',
          title: 'Client Private Key (PEM Format)',
          description: 'The private key corresponding to the X.509 client certificate'

    input :udap_jwt_signing_alg,
          title: 'JWT Signing Algorithm',
          description: %(
            Algorithm used to sign UDAP JSON Web Tokens (JWTs). UDAP Implementations SHALL support
            RS256.
            ),
          type: 'radio',
          options: {
            list_options: [
              {
                label: 'RS256',
                value: 'RS256'
              }
            ]
          },
          default: 'RS256',
          locked: true

    output :token_retrieval_time
    output :authorization_code_token_response_body
    makes_request :token_exchange

    config options: { redirect_uri: "#{Inferno::Application['base_url']}/custom/udap_security_test_kit/redirect" }

    run do
      client_assertion_payload = UDAPClientAssertionPayloadBuilder.build(
        udap_client_id,
        udap_token_endpoint,
        nil
      )

      x5c_certs = UDAPJWTBuilder.split_user_input_cert_string(udap_auth_code_flow_client_cert_pem)

      client_assertion_jwt = UDAPJWTBuilder.encode_jwt_with_x5c_header(
        client_assertion_payload,
        udap_auth_code_flow_client_private_key,
        udap_jwt_signing_alg,
        x5c_certs
      )

      token_exchange_headers, token_exchange_body =
        UDAPRequestBuilder.build_token_exchange_request(
          client_assertion_jwt,
          'authorization_code',
          udap_authorization_code,
          config.options[:redirect_uri]
        )

      post(udap_token_endpoint,
           body: token_exchange_body,
           name: :token_exchange,
           headers: token_exchange_headers)

      assert_response_status(200)
      assert_valid_json(request.response_body)

      output token_retrieval_time: Time.now.iso8601

      output authorization_code_token_response_body: request.response_body
    end
  end
end
