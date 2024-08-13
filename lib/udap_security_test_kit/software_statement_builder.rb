require 'jwt'

module UDAPSecurityTestKit
  class SoftwareStatementBuilder
    def self.build_payload(iss, aud, grant_type, scope)
      if grant_type == 'authorization_code'
        redirect_uris = ["#{Inferno::Application['base_url']}/custom/udap_security_test_kit/redirect"]
        response_types = ['code']
        client_name = 'Inferno UDAP Authorization Code Test Client'
      elsif grant_type == 'client_credentials'
        client_name = 'Inferno UDAP Client Credentials Test Client'
      end

      {
        iss:,
        sub: iss,
        aud:,
        exp: 5.minutes.from_now.to_i,
        iat: Time.now.to_i,
        jti: SecureRandom.hex(32),
        client_name:,
        redirect_uris:,
        contacts: ['mailto:inferno@groups.mitre.org'],
        logo_uri: 'https://inferno-framework.github.io/assets/inferno_logo.png',
        grant_types: [grant_type],
        response_types:,
        token_endpoint_auth_method: 'private_key_jwt',
        scope:
      }.compact
    end
  end
end
