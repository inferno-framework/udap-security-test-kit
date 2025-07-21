require_relative 'client_authentication_group/client_certificate_storage_test'
require_relative 'client_authentication_group/no_client_credentials_native_apps_test'

module UDAPSecurityTestKit
  class ClientAuthenticationGroup < Inferno::TestGroup
    id :udap_server_v100_client_authentication_group
    title 'Client Authentication and Credential Management'

    run_as_group
    test from: :udap_security_client_certificate_storage
    test from: :udap_security_no_client_credentials_native_apps
  end
end
