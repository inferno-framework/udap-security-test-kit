# frozen_string_literal: true

module UDAPSecurityTestKit
  FHIR_PATH = '/fhir'
  RESUME_PASS_PATH = '/resume_pass'
  RESUME_FAIL_PATH = '/resume_fail'
  AUTH_SERVER_PATH = '/auth'
  UDAP_DISCOVERY_PATH = "#{FHIR_PATH}/.well-known/udap".freeze
  TOKEN_PATH = "#{AUTH_SERVER_PATH}/token".freeze
  REGISTRATION_PATH = "#{AUTH_SERVER_PATH}/register".freeze

  module URLs
    def client_base_url
      @client_base_url ||= "#{Inferno::Application['base_url']}/custom/#{client_suite_id}"
    end

    def client_fhir_base_url
      @client_fhir_base_url ||= client_base_url + FHIR_PATH
    end

    def client_resume_pass_url
      @client_resume_pass_url ||= client_base_url + RESUME_PASS_PATH
    end

    def client_resume_fail_url
      @client_resume_fail_url ||= client_base_url + RESUME_FAIL_PATH
    end

    def client_udap_discovery_url
      @client_udap_discovery_url ||= client_base_url + UDAP_DISCOVERY_PATH
    end

    def client_token_url
      @client_token_url ||= client_base_url + TOKEN_PATH
    end

    def client_registration_url
      @client_registration_url ||= client_base_url + REGISTRATION_PATH
    end

    def client_suite_id
      UDAPSecurityTestKit::UDAPSecurityClientTestSuite.id
    end
  end
end
