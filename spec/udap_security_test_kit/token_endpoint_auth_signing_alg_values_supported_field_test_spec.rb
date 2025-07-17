require_relative '../../lib/udap_security_test_kit/token_endpoint_auth_signing_alg_values_supported_field_test'

RSpec.describe UDAPSecurityTestKit::TokenEndpointAuthSigningAlgValuesSupportedFieldTest do
  let(:suite_id) { 'udap_security' }
  let(:runnable) do
    find_test(suite, 'udap_token_endpoint_auth_signing_alg_values_supported_field')
  end

  it 'fails if field is not present' do
    config = {}

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('fail')
  end

  it 'passes if token_endpoint_auth_signing_alg_values_supported is an array of one or more strings' do
    config = { token_endpoint_auth_signing_alg_values_supported: ['RS256', 'ES384'] }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('pass')
  end

  it 'fails if token_endpoint_auth_signing_alg_values_supported is not an array' do
    config = { token_endpoint_auth_signing_alg_values_supported: 'RS256' }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('fail')
    expect(result.result_message).to match(/be an Array/)
  end

  it 'fails if token_endpoint_auth_signing_alg_values_supported is an array with a non-string element' do
    config = { token_endpoint_auth_signing_alg_values_supported: ['RS256', 1] }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('fail')
    expect(result.result_message).to match(/Array of strings/)
  end

  it 'fails if token_endpoint_auth_signing_alg_values_supported is an empty array' do
    config = { token_endpoint_auth_signing_alg_values_supported: [] }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('fail')
  end

  it 'fails if token_endpoint_auth_signing_alg_values_supported does not include required RS256 algorithm' do
    config = { token_endpoint_auth_signing_alg_values_supported: ['ES384'] }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('fail')
  end
end
