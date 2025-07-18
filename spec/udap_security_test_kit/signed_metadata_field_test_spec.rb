require_relative '../../lib/udap_security_test_kit/signed_metadata_field_test'

RSpec.describe UDAPSecurityTestKit::SignedMetadataFieldTest do
  let(:suite_id) { 'udap_security' }
  let(:runnable) { find_test(suite, 'udap_signed_metadata_field') }

  it 'fails if field is not present' do
    config = {}

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('fail')
  end

  it 'fails if signed_metadata is not a String' do
    config = { signed_metadata: 1 }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('fail')
    expect(result.result_message).to match(/be a String/)
  end

  it 'fails if signed_metadata is not a JWT' do
    config = { signed_metadata: 'abc' }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('fail')
    expect(result.result_message).to match(/not a valid JWT/)
  end

  it 'passes if signed_metadata is a JWT' do
    config = { signed_metadata: 'abc.def.xyz' }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('pass')
  end
end
