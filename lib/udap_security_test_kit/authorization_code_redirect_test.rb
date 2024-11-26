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
          description: 'Base FHIR URL of FHIR Server. Value for the aud parameter in the redirect URI.'

    input :udap_authorization_endpoint,
          title: 'Authorization Endpoint',
          description: 'The full URL from which Inferno will request an authorization code.'

    input :udap_client_id,
          title: 'Client ID',
          description: 'Client ID as registered with the authorization server.'

    input :udap_auth_code_flow_registration_scope,
          title: 'Requested Scopes',
          description: 'A list of space-separated scopes.',
          default: 'launch/patient openid fhirUser offline_access patient/*.read'

    output :udap_authorization_code_state

    receives_request :redirect

    config options: { redirect_uri: "#{Inferno::Application['base_url']}/custom/udap_security_test_kit/redirect" }

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
      output udap_authorization_code_state: SecureRandom.uuid

      oauth2_params = {
        'response_type' => 'code',
        'client_id' => udap_client_id,
        'redirect_uri' => config.options[:redirect_uri],
        'scope' => udap_auth_code_flow_registration_scope,
        'state' => udap_authorization_code_state,
        'aud' => udap_fhir_base_url
      }.compact

      authorization_url = authorization_url_builder(
        udap_authorization_endpoint,
        oauth2_params
      )

      info("Inferno redirecting browser to #{authorization_url}.")

      wait(
        identifier: udap_authorization_code_state,
        message: wait_message(authorization_url)
      )
    end
  end
end
