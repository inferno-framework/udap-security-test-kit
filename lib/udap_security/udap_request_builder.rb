require 'uri'
module UDAPSecurity
  class UDAPRequestBuilder
    def self.build_registration_request(software_statement_jwt, certifications_jwt)
      registration_headers = {
        'Accept' => 'application/json',
        'Content-Type' => 'application/json'
      }

      certifications = if certifications_jwt.nil?
                         []
                       else
                         certifications_jwt.split
                       end

      registration_body = {
        'software_statement' => software_statement_jwt,
        'certifications' => certifications,
        'udap' => '1'
      }.compact

      [registration_headers, registration_body.to_json]
    end

    def self.build_token_exchange_request(client_assertion_jwt, grant_type, authorization_code, redirect_uri)
      token_exchange_headers = {
        'Accept' => 'application/json',
        'Content-Type' => 'application/x-www-form-urlencoded'
      }

      token_exchange_body = {
        'grant_type' => grant_type,
        'code' => authorization_code,
        'redirect_uri' => redirect_uri,
        'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'client_assertion' => client_assertion_jwt,
        'udap' => '1'
      }.compact

      [token_exchange_headers, URI.encode_www_form(token_exchange_body)]
    end
  end
end
