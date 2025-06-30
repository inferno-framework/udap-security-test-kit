module UDAPSecurityTestKit
  class AuthenticationRequestConstructionAttestationTest < Inferno::Test
    title 'Authentication Request Construction Compliance'
    id :oidc_auth_request_construction
    description %(
      The Authorization Server SHALL ensure that authentication requests comply with OpenID Connect requirements, including:
      - Support for HTTP GET and POST methods at the Authorization Endpoint.
      - Inclusion of the `openid` scope value.
      - Presence and validity of required parameters such as `response_type`, `client_id`, and `redirect_uri`.
      - Exact matching of the `redirect_uri` with pre-registered values.
    )
    verifies_requirements 'hl7.fhir.us.udap-security@246',
                          'hl7.fhir.us.udap-security@247',
                          'hl7.fhir.us.udap-security@248',
                          'hl7.fhir.us.udap-security@249',
                          'hl7.fhir.us.udap-security@250',
                          'hl7.fhir.us.udap-security@251'

    input :auth_request_construction_correct,
          title: "Authentication Request Construction Compliance",
          description: %(
            I attest that the Authorization Server ensures:
            - HTTP GET and POST methods are supported at the Authorization Endpoint.
            - The `openid` scope value is included in requests.
            - Required parameters (`response_type`, `client_id`, `redirect_uri`) are present and valid.
            - The `redirect_uri` exactly matches pre-registered values.
          ),
          type: 'radio',
          default: 'false',
          options: {
            list_options: [
              {
                label: 'Yes',
                value: 'true'
              },
              {
                label: 'No',
                value: 'false'
              }
            ]
          }
    input :auth_request_construction_note,
          title: 'Notes, if applicable:',
          type: 'textarea',
          optional: true

    run do
      assert auth_request_construction_correct == 'true',
              'Authentication Request Construction does not comply with OpenID Connect requirements.'
      pass auth_request_construction_note if auth_request_construction_note.present?
    end
  end
end
