require_relative '../../lib/udap_security_test_kit/scopes_supported_field_test'

RSpec.describe UDAPSecurityTestKit::ScopesSupportedFieldTest do
  let(:suite_id) { 'udap_security' }
  let(:runnable) { find_test(suite, 'udap_scopes_supported_field') }

  it 'omits if field is not present' do
    config = {}

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('omit')
  end

  it 'passes if scopes_supported is an array of uri strings' do
    config = { scopes_supported: ['http://abc', 'http://def'] }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('pass')
  end

  it 'fails if scopes_supported is not an array' do
    config = { scopes_supported: 'http://abc' }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('fail')
    expect(result.result_message).to match(/be an Array/)
  end

  it 'fails if scopes_supported is an array with a non-string element' do
    config = { scopes_supported: ['http://abc', 1] }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('fail')
    expect(result.result_message).to match(/Array of strings/)
  end
end
