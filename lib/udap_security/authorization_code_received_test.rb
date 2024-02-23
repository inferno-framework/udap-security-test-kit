module UDAPSecurity
  class AuthorizationCodeReceivedTest < Inferno::Test
    title 'Authorization server sends code parameter'
    description %(
      Code is a required querystring parameter on the redirect.
    )
    id :udap_authorization_code_received

    output :udap_authorization_code
    uses_request :redirect

    run do
      code = request.query_parameters['code']
      output udap_authorization_code: code

      assert code.present?, 'No `code` parameter received'

      error = request.query_parameters['error']

      pass_if error.blank?

      error_message = "Error returned from authorization server. code: '#{error}'"
      error_description = request.query_parameters['error_description']
      error_uri = request.query_parameters['error_uri']
      error_message += ", description: '#{error_description}'" if error_description.present?
      error_message += ", uri: #{error_uri}" if error_uri.present?

      assert false, error_message
    end
  end
end
