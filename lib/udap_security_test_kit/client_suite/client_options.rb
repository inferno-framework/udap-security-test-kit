# frozen_string_literal: true

require_relative '../tags'

module UDAPSecurityTestKit
  module UDAPClientOptions
    module_function

    UDAP_AUTHORIZATION_CODE = "#{UDAP_TAG},#{AUTHORIZATION_CODE_TAG}".freeze
    UDAP_CLIENT_CREDENTIALS = "#{UDAP_TAG},#{CLIENT_CREDENTIALS_TAG}".freeze

    def oauth_flow(suite_options)
      if suite_options[:client_type].include?(AUTHORIZATION_CODE_TAG)
        AUTHORIZATION_CODE_TAG
      elsif suite_options[:client_type].include?(CLIENT_CREDENTIALS_TAG)
        CLIENT_CREDENTIALS_TAG
      end
    end
  end
end
