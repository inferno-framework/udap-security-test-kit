require_relative '../mock_udap_server'

module UDAPSecurityTestKit
  module MockUDAPServer
    module UDAPRegistrationResponseCreation
      def make_udap_registration_response
        parsed_body = MockUDAPServer.parsed_io_body(request)
        client_id = MockUDAPServer.client_uri_to_client_id(
          MockUDAPServer.udap_client_uri_from_registration_payload(parsed_body)
        )
        ss_jwt = MockUDAPServer.udap_software_statement_jwt(parsed_body)

        response_body = {
          client_id:,
          software_statement: ss_jwt
        }
        response_body.merge!(MockUDAPServer.jwt_claims(ss_jwt).except(['iss', 'sub', 'exp', 'iat', 'jti']))

        response.body = response_body.to_json
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.content_type = 'application/json'
        response.status = 201
      end
    end
  end
end
