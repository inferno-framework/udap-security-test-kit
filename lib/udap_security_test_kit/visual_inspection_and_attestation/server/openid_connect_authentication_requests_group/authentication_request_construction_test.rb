module UDAPSecurityTestKit
  class AuthenticationRequestConstructionAttestationTest < Inferno::Test
    title 'Complies with OpenID Connect requirements in construction'
    id :oidc_auth_request_construction
    description %(
      Authorization Server complies ith OpenID Connect requirements and ensures:
      - HTTP GET and POST methods are supported at the Authorization Endpoint.
      - The `openid` scope value is included in requests.
      - Required parameters (`response_type`, `client_id`, `redirect_uri`) are present and valid.
      - The `redirect_uri` exactly matches pre-registered values.
    )
    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0@246',
                          'hl7.fhir.us.udap-security_1.0.0@247',
                          'hl7.fhir.us.udap-security_1.0.0@248',
                          'hl7.fhir.us.udap-security_1.0.0@249',
                          'hl7.fhir.us.udap-security_1.0.0@250',
                          'hl7.fhir.us.udap-security_1.0.0@251'

    input :auth_request_construction_correct,
          title: 'OpenID Connect Authentication Requests: Complies with OpenID Connect requirements',
          description: %(
            I attest that the Authorization Server complies with OpenID Connect requirements and ensures:
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
