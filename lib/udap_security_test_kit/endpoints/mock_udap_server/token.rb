# frozen_string_literal: true

require_relative '../../urls'
require_relative '../../tags'
require_relative '../mock_udap_server'

module UDAPSecurityTestKit
  module MockUdapServer
    class TokenEndpoint < Inferno::DSL::SuiteEndpoint
      def test_run_identifier
        client_id_from_client_assertion(request.params[:client_assertion])
      end

      def make_response
        assertion = request.params[:client_assertion]
        client_id = client_id_from_client_assertion(assertion)

        software_statement = MockUdapServer.udap_registration_software_statement(test_run.test_session_id)
        signature_error = MockUdapServer.udap_assertion_signature_verification(assertion, software_statement)

        if signature_error.present?
          MockUdapServer.update_response_for_invalid_assertion(response, signature_error)
          return
        end

        exp_min = 60
        response_body = {
          access_token: MockUdapServer.client_id_to_token(client_id, exp_min),
          token_type: 'Bearer',
          expires_in: 60 * exp_min
        }

        response.body = response_body.to_json
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.content_type = 'application/json'
        response.status = 200
      end

      def update_result
        nil # never update for now
      end

      def tags
        [TOKEN_TAG, UDAP_TAG]
      end

      private

      def client_id_from_client_assertion(client_assertion_jwt)
        return unless client_assertion_jwt.present?

        MockUdapServer.jwt_claims(client_assertion_jwt)&.dig('iss')
      end
    end
  end
end
