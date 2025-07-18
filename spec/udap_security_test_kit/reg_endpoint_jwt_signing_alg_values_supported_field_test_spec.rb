require_relative '../../lib/udap_security_test_kit/reg_endpoint_jwt_signing_alg_values_supported_field_test'

RSpec.describe UDAPSecurityTestKit::RegEndpointJWTSigningAlgValuesSupportedFieldTest do
  let(:suite_id) { 'udap_security' }
  let(:runnable) { find_test(suite, 'udap_reg_endpoint_jwt_signing_alg_values_supported_field') }

  it 'omits if field is not present' do
    config = {}

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('omit')
  end

  it 'passes if registration_endpoint_jwt_signing_alg_values_supported is an array strings' do
    config = { registration_endpoint_jwt_signing_alg_values_supported: ['ES384', 'RS256'] }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('pass')
  end

  it 'fails if registration_endpoint_jwt_signing_alg_values_supported is not an array' do
    config = { registration_endpoint_jwt_signing_alg_values_supported: 'RS256' }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('fail')
    expect(result.result_message).to match(/be an Array/)
  end

  it 'fails if registration_endpoint_jwt_signing_alg_values_supported is an array with a non-string element' do
    config = { registration_endpoint_jwt_signing_alg_values_supported: ['RS256', 1] }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('fail')
    expect(result.result_message).to match(/Array of strings/)
  end

  it 'fails if registration_endpoint_jwt_signing_alg_values_supported is an empty array' do
    config = { registration_endpoint_jwt_signing_alg_values_supported: [] }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('fail')
  end

  it 'fails if registration_endpoint_jwt_signing_alg_values_supported does not include required RS256 algorithm' do
    config = { registration_endpoint_jwt_signing_alg_values_supported: ['ES384'] }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('fail')
    expect(result.result_message).to match(/must support RS256/)
  end
end
