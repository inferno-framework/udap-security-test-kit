# frozen_string_literal: true

require_relative '../../tags'
require_relative '../../urls'
require_relative '../mock_udap_server'
require_relative 'udap_response_creation'

module UDAPSecurityTestKit
  module MockUDAPServer
    class TokenEndpoint < Inferno::DSL::SuiteEndpoint
      include UDAPResponseCreation
      include URLs

      def test_run_identifier
        case request.params[:grant_type]
        when CLIENT_CREDENTIALS_TAG
          MockUDAPServer.client_id_from_client_assertion(request.params[:client_assertion])
        when AUTHORIZATION_CODE_TAG
          MockUDAPServer.issued_token_to_client_id(request.params[:code])
        when REFRESH_TOKEN_TAG
          MockUDAPServer.issued_token_to_client_id(
            MockUDAPServer.refresh_token_to_authorization_code(request.params[:refresh_token])
          )
        end
      end

      def make_response
        case request.params[:grant_type]
        when CLIENT_CREDENTIALS_TAG
          make_udap_client_credential_token_response
        when AUTHORIZATION_CODE_TAG
          make_udap_authorization_code_token_response
        when REFRESH_TOKEN_TAG
          make_udap_refresh_token_response
        else
          MockUDAPServer.update_response_for_invalid_assertion(
            response,
            "unsupported grant_type: #{request.params[:grant_type]}"
          )
        end
      end

      def update_result
        nil # never update for now
      end

      def tags
        tags = [TOKEN_TAG, UDAP_TAG]
        if [CLIENT_CREDENTIALS_TAG, AUTHORIZATION_CODE_TAG, REFRESH_TOKEN_TAG].include?(request.params[:grant_type])
          tags << request.params[:grant_type]
        end
        tags
      end
    end
  end
end
