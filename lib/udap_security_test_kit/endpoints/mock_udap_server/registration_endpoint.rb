# frozen_string_literal: true

require_relative '../../tags'
require_relative '../mock_udap_server'
require_relative 'udap_response_creation'

module UDAPSecurityTestKit
  module MockUDAPServer
    class RegistrationEndpoint < Inferno::DSL::SuiteEndpoint
      include UDAPResponseCreation

      def test_run_identifier
        MockUDAPServer.client_uri_to_client_id(
          MockUDAPServer.udap_client_uri_from_registration_payload(MockUDAPServer.parsed_io_body(request))
        )
      end

      def make_response
        make_udap_registration_response
      end

      def update_result
        nil # never update for now
      end

      def tags
        [REGISTRATION_TAG, UDAP_TAG]
      end
    end
  end
end
