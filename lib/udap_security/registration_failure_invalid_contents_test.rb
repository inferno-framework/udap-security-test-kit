require_relative 'software_statement_builder'
require_relative 'udap_jwt_builder'

module UDAPSecurity
  class RegistrationFailureInvalidContentsTest < Inferno::Test
    title 'Dynamic Client Registration request fails with improper software statement contents'
    id :udap_registration_failure_invalid_contents
    description %(
      The [UDAP IG Section 3.1](https://hl7.org/fhir/us/udap-security/STU1/registration.html#software-statement) states:
      > The unique client URI used for the iss claim SHALL match the uriName entry in the Subject Alternative Name
      > extension of the client app operator’s X.509 certificate, and SHALL uniquely identify a single client app
      > operator and application over time

      The [UDAP IG Section 3.2.3](https://hl7.org/fhir/us/udap-security/STU1/registration.html#request-body) states:
      > The Authorization Server SHALL validate the registration request as per Section 4 of UDAP Dynamic Client
      > Registration. This includes validation of the JWT payload and signature, validation of the X.509 certificate
      > chain, and **validation of the requested application registration parameters**.

      This test will provide a software statement whose `iss` value does not match the uriName entry in the client's
      certificate.  The authorization server must reject this request with a 400 response code per
      [RFC 7591 OAuth 2.0 Dynamic Client Registration Protocol Section 3.2.2](https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.2):
      > When a registration error condition occurs, the authorization server
      *returns an HTTP 400 status code* (unless otherwise specified) with
      content type "application/json" consisting of a JSON object
      describing the error in the response body.
    )

    input :udap_client_cert_pem
    input :udap_client_private_key_pem

    input :udap_registration_endpoint
    input :udap_jwt_signing_alg
    input :udap_registration_requested_scope
    input :udap_registration_grant_type
    input :udap_registration_certifications,
          optional: true

    run do
      software_statement_payload = SoftwareStatementBuilder.build_payload(
        'invalid_iss',
        udap_registration_endpoint,
        udap_registration_grant_type,
        udap_registration_requested_scope
      )

      signed_jwt = UDAPSecurity::UDAPJWTBuilder.encode_jwt_with_x5c_header(
        software_statement_payload,
        udap_client_private_key_pem,
        udap_jwt_signing_alg,
        [udap_client_cert_pem]
      )

      registration_headers, registration_body = UDAPSecurity::UDAPRequestBuilder.build_registration_request(
        signed_jwt,
        udap_registration_certifications
      )

      post(udap_registration_endpoint, body: registration_body, headers: registration_headers)

      assert_response_status(400)
      assert_valid_json(response[:body])
    end
  end
end
