require_relative 'udap_client_assertion_payload_builder'

module UDAPSecurity
  class ClientCredentialsTokenExchangeTest < Inferno::Test
    title 'OAuth token exchange request succeeds when supplied correct information'
    description %(
      The [UDAP Security IG Section 5.2 on Obtaining an Access Token](https://hl7.org/fhir/us/udap-security/STU1/b2b.html#obtaining-an-access-token)
      states the following:
      - The client SHALL use its private key to sign an Authentication
        Token ... and include this JWT in the
        client_assertion parameter of its token request
      - Client applications using the client credentials grant and
        authenticating with a private key and
        Authentication Token as per Section 5.2.1 SHALL submit a POST request to the Authorization Server’s token
        endpoint
      - An Authorization Server receiving token requests containin
        Authentication Tokens as above SHALL validate and
        respond to the request as per Sections 6 and 7 of UDAP JWT-Based Client Authentication.

      Furthermore, the inclusion of an `extensions` claim in the Authentication JWT is required for B2B client apps
      using the client credentials flow.  Inferno provides an extensions object with the following information:
      - `'version'`: `'1'`
      - `'subject_name'`: `'UDAP Test Kit'`
      - `'organization_name'`: `'Inferno Framework'`
      - `'organization_id'`: `'https://inferno-framework.github.io/'`
      - `'purpose_of_use'`: `['SYSDEV']`

      This test creates an authentication JWT, POSTs a token request to the server's token endpoint, and expects a 200
      response.
    )
    id :udap_client_credentials_token_exchange

    input :udap_client_id,
          title: 'Client ID',
          description: 'Client ID as registered with the authorization server.'

    input :udap_token_endpoint,
          title: 'Token Endpoint',
          description: 'The full URL from which Inferno will request an access token'

    input :udap_client_cert_pem_client_creds_flow,
          title: 'X.509 Client Certificate(s) (PEM Format)',
          type: 'textarea',
          description: %(
            A list of one or more X.509 certificates in PEM format separated by a newline. The first (leaf) certificate
            MUST represent the client entity Inferno registered as,
            and the trust chain that will be built from the provided certificate(s) must resolve to a CA trusted by the
            authorization server under test.
          )

    input :udap_client_private_key_client_creds_flow,
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
    output :client_credentials_token_response_body
    makes_request :token_exchange

    run do
      # SYSDEV purpose of use definition:
      # "To perform one or more operations on information to design, develop
      # implement, test, or deploy a healthcare system or application."
      # See https://terminology.hl7.org/5.5.0/ValueSet-v3-PurposeOfUse.html
      extensions = {
        'hl7-b2b' => {
          'version' => '1',
          'subject_name' => 'UDAP Test Kit',
          'organization_name' => 'Inferno Framework',
          'organization_id' => 'https://inferno-framework.github.io/',
          'purpose_of_use' => ['SYSDEV']
        }
      }

      client_assertion_payload = UDAPClientAssertionPayloadBuilder.build(
        udap_client_id,
        udap_token_endpoint,
        extensions.to_json
      )

      x5c_certs = UDAPSecurity::UDAPJWTBuilder.split_user_input_cert_string(
        udap_client_cert_pem_client_creds_flow
      )

      client_assertion_jwt = UDAPSecurity::UDAPJWTBuilder.encode_jwt_with_x5c_header(
        client_assertion_payload,
        udap_client_private_key_client_creds_flow,
        udap_jwt_signing_alg,
        x5c_certs
      )

      token_exchange_headers, token_exchange_body = UDAPSecurity::UDAPRequestBuilder.build_token_exchange_request(
        client_assertion_jwt,
        'client_credentials',
        nil,
        nil
      )

      post(udap_token_endpoint,
           body: token_exchange_body,
           name: :token_exchange,
           headers: token_exchange_headers)

      assert_response_status(200)
      assert_valid_json(request.response_body)

      output token_retrieval_time: Time.now.iso8601

      output client_credentials_token_response_body: request.response_body
    end
  end
end
