require_relative '../tags'
require_relative '../endpoints/mock_udap_server'

module UDAPSecurityTestKit
  class UDAPTokenUseVerification < Inferno::Test
    id :udap_client_token_use_verification
    title 'Verify UDAP Token Use'
    description %(
        Check that a UDAP token returned to the client was used for request
        authentication.
      )

    input :udap_demonstrated # from test :udap_client_token_request_verification based on registrations
    input :udap_tokens,
          optional: true

    def access_request_tags
      return config.options[:access_request_tags] if config.options[:access_request_tags].present?

      [ACCESS_TAG]
    end

    run do
      omit_if udap_demonstrated == 'No', 'UDAP Authentication not demonstrated as a part of this test session.'

      access_requests = access_request_tags.map do |access_request_tag|
        load_tagged_requests(access_request_tag).reject { |access| access.status == 401 }
      end.flatten
      obtained_tokens = udap_tokens&.split("\n")

      skip_if obtained_tokens.blank?, 'No token requests made.'
      skip_if access_requests.blank?, 'No successful access requests made.'

      used_tokens = access_requests.map do |access_request|
        access_request.request_headers.find do |header|
          header.name.downcase == 'authorization'
        end&.value&.delete_prefix('Bearer ')
      end.compact

      assert (used_tokens & obtained_tokens).present?, 'Returned tokens never used in any requests.'
    end
  end
end
