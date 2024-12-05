module UDAPSecurityTestKit
  class RegistrationSuccessContentsTest < Inferno::Test
    title 'Successful Dynamic Client Registration request response contains required contents'
    id :udap_registration_success_contents
    description %(
      The [UDAP IG Section 3.2.3](https://hl7.org/fhir/us/udap-security/STU1/registration.html#request-body) states:
      > If a new registration is successful, the Authorization Server SHALL return a registration response with a 201
      > Created HTTP response code as per Section 5.1 of UDAP Dynamic Client Registration, including the unique
      > client_id assigned by the Authorization Server to that client app.

      And the [UDAP Profile Section 5.1](https://www.udap.org/udap-dynamic-client-registration-stu1.html#section-5.1)
       states:
      > If the request is granted, the Authorization Server returns a registration response as per Section 3.2.1 of RFC
      > 7591. The top-level elements of the response SHALL include the client_id issued by the Authorization Server for
      > use by the Client App, the software statement as submitted by the Client App, and all of the registration
      > related parameters that were included in the software statement.

      [UDAP STU 1.1](https://hl7.org/fhir/us/udap-security/STU1.1/registration.html#request-body) clarifies that,
      in accordance with [Section 3.2.1 of RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.1):
        > The authorization server MAY reject or replace any of the client's requested metadata values submitted during
        > the registration and substitute them with suitable values.

      This test verifies:
      - `client_id` claim is present in the registration response and its value is not blank.
      - `scope` and `client_name` claims are present in the registration response and their values are not blank.
      - `software_statement`, `grant_types`, and `token_endpoint_auth_method` claims are present in the registration
      response and their values match those in the originally submitted software statement.
      - If the registered grant type is `authorization_code`, then the `redirect_uris` and `response_type` claims are
      present in the registration response and their values match in the originally submitted software statement.

      In order for downstream tests to succeed, it is
      essential that the client and server are in agreement on the values of most of the software statement
      parameters. The exception is `client_name`, which does not impact behavior. For this reason, an exact match
      between the request and response values for `client_name` is not required.
      Additionally, an exact match between `scope` request and response value is also not required because the
      authorization server may grant different scopes than those orignally requested by the client.
    )

    input :udap_software_statement_json
    input :udap_software_statement_jwt
    input :udap_registration_response
    input :udap_registration_grant_type

    output :udap_client_id

    run do
      assert_valid_json(udap_registration_response)
      registration_response = JSON.parse(udap_registration_response)

      assert registration_response.key?('client_id'), 'Successful registration response must contain a client_id'
      client_id = registration_response['client_id']
      assert client_id.present?, 'client_id cannot be blank'

      output udap_client_id: client_id

      assert registration_response['software_statement'] == udap_software_statement_jwt,
             'Successful registration response must include the ' \
             'software statement JWT submitted by client'

      original_software_statement = JSON.parse(udap_software_statement_json)

      expected_claims = ['scope', 'client_name', 'grant_types', 'token_endpoint_auth_method']
      auth_code_claims = ['redirect_uris', 'response_types']

      # For this subset, authorization server may return a different value than
      # the one originally provided in client software statement
      mutable_claims = ['scope', 'client_name']

      expected_claims.concat auth_code_claims if udap_registration_grant_type == 'authorization_code'

      expected_claims.each do |claim|
        assert registration_response.key?(claim), "Successful registration response must include #{claim} claim"
        assert registration_response[claim].present?, "`#{claim}` value cannot be blank"
        next if mutable_claims.include?(claim)

        assert registration_response[claim] == original_software_statement[claim],
               "Registration response value for #{claim} does not match " \
               'value in client-submitted software statement'
      end
    end
  end
end
