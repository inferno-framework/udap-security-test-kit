require_relative 'software_statement_builder'
require_relative 'udap_jwt_builder'

module UDAPSecurityTestKit
  class RegistrationSuccessTest < Inferno::Test
    title 'Dynamic Client Registration request succeeds with valid software statement, JWT signature, and client certs'

    id :udap_registration_success
    description %(
      When the Dynamic Client registration request includes a properly signed software statement JWT with the required
      contents, the registration request should succeed.

      The [UDAP IG Section 3.2.3](https://hl7.org/fhir/us/udap-security/STU1/registration.html#request-body) states:
      > If a new registration is successful, the Authorization Server SHALL return a registration response with a 201
      > Created HTTP response code as per Section 5.1 of UDAP Dynamic Client Registration

      If the tester indicated this registration attempt represents a modification of an existing registration entry,
      the [UDAP IG Section 3.4](https://hl7.org/fhir/us/udap-security/STU1/registration.html#modifying-and-cancelling-registrations)
      states:
      > If the Authorization Server returns the same client_id in the registration response for a modification request,
      > it SHOULD also return a 200 OK HTTP response code.

      In this case, the test will require either a 201 or 200 response code to pass.
    )

    input :udap_client_cert_pem
    input :udap_client_private_key_pem
    input :udap_cert_iss

    input :udap_registration_endpoint
    input :udap_client_registration_status
    input :udap_jwt_signing_alg
    input :udap_registration_requested_scope
    input :udap_registration_grant_type
    input :udap_registration_certifications,
          optional: true

    output :udap_software_statement_jwt
    output :udap_software_statement_json
    output :udap_registration_response

    run do
      software_statement_payload = SoftwareStatementBuilder.build_payload(
        udap_cert_iss,
        udap_registration_endpoint,
        udap_registration_grant_type,
        udap_registration_requested_scope
      )

      output udap_software_statement_json: software_statement_payload.to_json

      x5c_certs = UDAPSecurityTestKit::UDAPJWTBuilder.split_user_input_cert_string(
        udap_client_cert_pem
      )

      signed_jwt = UDAPSecurityTestKit::UDAPJWTBuilder.encode_jwt_with_x5c_header(
        software_statement_payload,
        udap_client_private_key_pem,
        udap_jwt_signing_alg,
        x5c_certs
      )

      output udap_software_statement_jwt: signed_jwt

      reg_headers, reg_body = UDAPSecurityTestKit::UDAPRequestBuilder.build_registration_request(
        signed_jwt,
        udap_registration_certifications
      )

      post(udap_registration_endpoint, body: reg_body, headers: reg_headers)

      if udap_client_registration_status == 'new'
        assert_response_status(201)
      elsif udap_client_registration_status == 'update'
        assert_response_status([200, 201])
      end

      assert_valid_json(response[:body])
      output udap_registration_response: response[:body]
    end
  end
end
