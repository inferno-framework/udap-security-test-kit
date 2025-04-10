# frozen_string_literal: true

require_relative '../../urls'
require_relative '../../tags'
require_relative '../mock_udap_server'

module UDAPSecurityTestKit
  module MockUDAPServer
    class TokenEndpoint < Inferno::DSL::SuiteEndpoint
      def test_run_identifier
        MockUDAPServer.client_id_from_client_assertion(request.params[:client_assertion])
      end

      def make_response
        MockUDAPServer.make_udap_token_response(request, response, test_run.test_session_id)
      end

      def update_result
        nil # never update for now
      end

      def tags
        [TOKEN_TAG, UDAP_TAG]
      end
    end
  end
end
