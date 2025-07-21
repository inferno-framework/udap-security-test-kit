require_relative '../../lib/udap_security_test_kit/udap_versions_supported_field_test'

RSpec.describe UDAPSecurityTestKit::UDAPVersionsSupportedFieldTest do
  let(:suite_id) { 'udap_security' }
  let(:runnable) { find_test suite, 'udap_versions_supported_field' }

  it 'fails if field is not ["1"]' do
    config = {}

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('fail')
    expect(result.result_message).to match('must contain an array')
  end

  it 'passes if udap_versions_supported is ["1"]' do
    config = { udap_versions_supported: ['1'] }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('pass')
  end
end
