# frozen_string_literal: true

require_relative '../../tags'
require_relative '../mock_udap_server'
require_relative 'udap_introspection_response_creation'

module UDAPSecurityTestKit
  module MockUDAPServer
    class IntrospectionEndpoint < Inferno::DSL::SuiteEndpoint
      include UDAPIntrospectionResponseCreation

      def test_run_identifier
        MockUDAPServer.issued_token_to_client_id(request.params[:token])
      end

      def make_response
        response.body = make_udap_introspection_response.to_json
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
        [INTROSPECTION_TAG, UDAP_TAG]
      end
    end
  end
end
