# frozen_string_literal: true

require_relative '../../urls'
require_relative '../../tags'
require_relative '../mock_udap_server'

module UDAPSecurityTestKit
  module MockUDAPServer
    class AuthorizationEndpoint < Inferno::DSL::SuiteEndpoint
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
        [AUTHORIZATION_TAG, UDAP_TAG]
      end

      def make_udap_authorization_response
        redirect_uri = request.params[:redirect_uri]
        registered_redirect_uri_list = registered_redirect_uris

        if redirect_uri.blank?
          # need one from the registered list
          if registered_redirect_uri_list.blank?
            response.status = 400
            response.body = {
              error: 'Bad request',
              message: 'Missing required redirect_uri parameter with no default provided in the registration.'
            }.to_json
            response.content_type = 'application/json'
            return
          elsif registered_redirect_uri_list.length > 1
            response.status = 400
            response.body = {
              error: 'Bad request',
              message: 'Missing required redirect_uri parameter with multiple options provided in the registration.'
            }.to_json
            response.content_type = 'application/json'
            return
          else
            redirect_uri = registered_redirect_uri_list.first
          end
        end

        client_id = request.params[:client_id]
        state = request.params[:state]

        exp_min = 10
        token = MockUDAPServer.client_id_to_token(client_id, exp_min)
        code_query_string = "code=#{ERB::Util.url_encode(token)}"
        query_string =
          if state.present?
            "#{code_query_string}&state=#{ERB::Util.url_encode(state)}"
          else
            code_query_string
          end
        response.headers['Location'] = "#{redirect_uri}#{redirect_uri.include?('?') ? '&' : '?'}#{query_string}"
        response.status = 302
      end

      def registered_redirect_uris
        registered_software_statement = MockUDAPServer.udap_registration_software_statement(test_run.test_session_id)
        registration_jwt_body, _registration_jwt_header = JWT.decode(registered_software_statement, nil, false)
        return [] unless registration_jwt_body['redirect'].present?
        return registration_jwt_body['redirect'] if registration_jwt_body['redirect'].is_a?(Array)

        # invalid registration, but we'll succeed here and fail during registration verification
        [registration_jwt_body['redirect']]
      end
    end
  end
end
