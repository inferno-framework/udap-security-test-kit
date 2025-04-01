require_relative '../tags'
require_relative '../urls'
require_relative '../endpoints/mock_udap_server'

module UDAPSecurityTestKit
  class UDAPTokenUseVerification < Inferno::Test
    include URLs

    id :udap_client_token_use_verification
    title 'Verify UDAP Token Use'
    description %(
        Check that a UDAP token returned to the client was used for request
        authentication.
      )

    def access_request_tags
      return config.options[:access_request_tags] if config.options[:access_request_tags].present?

      [ACCESS_TAG]
    end

    run do
      load_tagged_requests(REGISTRATION_TAG, UDAP_TAG)
      omit_if requests.blank?, 'UDAP Authentication not demonstrated as a part of this test session.'

      requests.clear
      token_requests = load_tagged_requests(TOKEN_TAG, UDAP_TAG)

      puts access_request_tags
      puts config.options
      access_requests = access_request_tags.map do |access_request_tag|
        load_tagged_requests(access_request_tag).reject { |access| access.status == 401 }
      end.flatten

      skip_if token_requests.blank?, 'No token requests made.'
      skip_if access_requests.blank?, 'No successful access requests made.'

      used_tokens = access_requests.map do |access_request|
        access_request.request_headers.find do |header|
          header.name.downcase == 'authorization'
        end&.value&.delete_prefix('Bearer ')
      end.compact

      request_with_used_token = token_requests.find do |token_request|
        used_tokens.include?(JSON.parse(token_request.response_body)&.dig('access_token'))
      end

      assert request_with_used_token.present?, 'Returned tokens never used in any requests.'
    end
  end
end
