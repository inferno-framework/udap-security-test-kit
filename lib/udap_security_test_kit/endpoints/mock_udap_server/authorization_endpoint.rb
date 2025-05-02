# frozen_string_literal: true

require_relative '../../tags'
require_relative 'udap_authorization_response_creation'

module UDAPSecurityTestKit
  module MockUDAPServer
    class AuthorizationEndpoint < Inferno::DSL::SuiteEndpoint
      include UDAPAuthorizationResponseCreation

      def test_run_identifier
        request.params[:client_id]
      end

      def make_response
        make_udap_authorization_response
      end

      def update_result
        nil # never update for now
      end

      def tags
        [AUTHORIZATION_TAG, AUTHORIZATION_CODE_TAG, UDAP_TAG]
      end
    end
  end
end
