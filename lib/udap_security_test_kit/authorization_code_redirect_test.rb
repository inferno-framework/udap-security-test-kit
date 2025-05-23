require_relative '../udap_security_test_kit'
module UDAPSecurityTestKit
  class AuthorizationCodeRedirectTest < Inferno::Test
    title 'Authorization server redirects client to redirect URI'
    id :udap_authorization_code_redirect
    description %(
        Per [RFC 6749 OAuth 2.0 Authorization Framework Section 4.1.1](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1),
        once the server validates the client's authorization request, the authorization server directs the user-agent to
        the provided client redirection URI using an HTTP redirection response.
      )

    input :udap_fhir_base_url,
          title: 'FHIR Server Base URL',
          description: 'Base FHIR URL of FHIR Server.'

    input :udap_authorization_endpoint,
          title: 'Authorization Endpoint',
          description: 'The full URL from which Inferno will request an authorization code.'

    input :udap_client_id,
          title: 'Client ID',
          description: 'Client ID as registered with the authorization server.'

    input :udap_authorization_code_request_scopes,
          title: 'Scope Parameter for Authorization Request',
          description: %(
              A list of space-separated scopes to include in the authorization request. If included, these may be equal
              to or a subset of the scopes requested during registration.
              If empty, scope will be omitted as a parameter to the authorization endpoint.
          ),
          optional: true

    input :udap_authorization_code_request_aud,
          title: "Audience ('aud') Parameter for Authorization Request",
          type: 'checkbox',
          options: {
            list_options: [
              {
                label: "Include 'aud' parameter",
                value: 'include_aud'
              }
            ]
          },
          description: %(
              If selected, the Base FHIR URL will be used as the 'aud' parameter in the request to the authorization
              endpoint.
          ),
          optional: true

    output :udap_authorization_code_state
    output :udap_authorization_redirect_url

    receives_request :redirect

    verifies_requirements 'hl7.fhir.us.udap-security_1.0.0_reqs@133',
                          'hl7.fhir.us.udap-security_1.0.0_reqs@190'

    config options: {
      redirect_uri: UDAPSecurityTestKit::UDAP_REDIRECT_URI
    }

    def wait_message(auth_url)
      if config.options[:redirect_message_proc].present?
        return instance_exec(auth_url, &config.options[:redirect_message_proc])
      end

      %(
        ### #{self.class.parent&.parent&.title}

        [Follow this link to authorize with the auth server](#{auth_url}).

        Tests will resume once Inferno receives a request at
        `#{config.options[:redirect_uri]}` with a state of `#{udap_authorization_code_state}`.
      )
    end

    def authorization_url_builder(url, params)
      uri = URI(url)

      # because the URL might have parameters on it
      original_parameters = URI.decode_www_form(uri.query || '').to_h
      new_params = original_parameters.merge(params)

      uri.query = URI.encode_www_form(new_params)
      uri.to_s
    end

    run do
      assert_valid_http_uri(
        udap_authorization_endpoint,
        "UDAP authorization endpoint '#{udap_authorization_endpoint}' is not a valid URI"
      )

      output udap_authorization_code_state: SecureRandom.uuid

      aud = udap_fhir_base_url if udap_authorization_code_request_aud.include? 'include_aud'

      oauth2_params = {
        'response_type' => 'code',
        'client_id' => udap_client_id,
        'redirect_uri' => config.options[:redirect_uri],
        'state' => udap_authorization_code_state,
        'scope' => udap_authorization_code_request_scopes,
        'aud' => aud
      }.compact

      authorization_url = authorization_url_builder(
        udap_authorization_endpoint,
        oauth2_params
      )

      info("Inferno redirecting browser to #{authorization_url}.")

      output udap_authorization_redirect_url: authorization_url

      wait(
        identifier: udap_authorization_code_state,
        message: wait_message(authorization_url)
      )
    end
  end
end
