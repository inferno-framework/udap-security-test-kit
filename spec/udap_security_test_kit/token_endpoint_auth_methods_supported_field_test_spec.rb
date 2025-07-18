require_relative '../../lib/udap_security_test_kit/token_endpoint_auth_methods_supported_field_test'

RSpec.describe UDAPSecurityTestKit::TokenEndpointAuthMethodsSupportedFieldTest do
  let(:suite_id) { 'udap_security' }
  let(:runnable) { find_test(suite, 'udap_token_endpoint_auth_methods_supported_field') }

  it 'fails if field is not present' do
    config = {}

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('fail')
  end

  it 'passes if token_endpoint_auth_methods_supported is ["private_key_jwt"]' do
    config = { token_endpoint_auth_methods_supported: ['private_key_jwt'] }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('pass')
  end

  it 'fails if token_endpoint_auth_methods_supported is not ["private_key_jwt"]' do
    config = { token_endpoint_auth_methods_supported: 'abc' }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('fail')
    expect(result.result_message).to match(/must contain an array with/)
  end
end
