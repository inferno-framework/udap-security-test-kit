require_relative 'software_statement_builder'
require_relative 'udap_jwt_builder'
require_relative 'udap_request_builder'

module UDAPSecurity
  class RegistrationFailureInvalidJWTSignatureTest < Inferno::Test
    title 'Dynamic Client Registration request fails when software statement JWT is improperly signed'
    id :udap_registration_failure_invalid_jwt_signature
    description %(
      The [UDAP IG Section 3.2.3](https://hl7.org/fhir/us/udap-security/STU1/registration.html#request-body) states:
      > The Authorization Server SHALL validate the registration request as per Section 4 of UDAP Dynamic Client
      > Registration. This includes **validation of the JWT payload and signature**, validation of the X.509 certificate
      > chain, and validation of the requested application registration parameters.

      Additionally, the [UDAP IG Section 1.2.3](https://hl7.org/fhir/us/udap-security/STU1/#jwt-headers) states that the
      required `x5c` JWT header value is "An array of one or more strings containing the X.509 certificate or
      certificate chain, where **the leaf certificate corresponds to the key used to digitally sign the JWT.**"

      This test will provide a software statement signed with a randomly generated private key that does not correspond
      to the client certificate included in the x5c header claim.
      The authorization server must reject this request with a 400 response code per
      [RFC 7591 OAuth 2.0 Dynamic Client Registration Protocol Section 3.2.2](https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.2):
      > When a registration error condition occurs, the authorization server
      *returns an HTTP 400 status code* (unless otherwise specified) with
      content type "application/json" consisting of a JSON object
      describing the error in the response body.
    )

    input :udap_client_cert_pem
    input :udap_cert_iss

    input :udap_registration_endpoint
    input :udap_jwt_signing_alg
    input :udap_registration_requested_scope
    input :udap_registration_grant_type
    input :udap_registration_certifications,
          optional: true

    run do
      software_statement_payload = SoftwareStatementBuilder.build_payload(
        udap_cert_iss,
        udap_registration_endpoint,
        udap_registration_grant_type,
        udap_registration_requested_scope
      )

      random_private_key = OpenSSL::PKey::RSA.generate 2048
      signed_jwt = UDAPSecurity::UDAPJWTBuilder.encode_jwt_with_x5c_header(
        software_statement_payload,
        random_private_key.to_pem,
        udap_jwt_signing_alg,
        [udap_client_cert_pem]
      )

      reg_headers, reg_body = UDAPSecurity::UDAPRequestBuilder.build_registration_request(
        signed_jwt,
        udap_registration_certifications
      )

      post(udap_registration_endpoint, body: reg_body, headers: reg_headers)

      assert_response_status(400)
      assert_valid_json(response[:body])
    end
  end
end
