require_relative '../../lib/udap_security_test_kit/udap_certifications_required_field_test'

RSpec.describe UDAPSecurityTestKit::UDAPCertificationsRequiredFieldTest do
  let(:suite_id) { 'udap_security' }
  let(:runnable) { find_test(suite, 'udap_certifications_required_field') }

  it 'skips if udap_certifications_supported field is not present' do
    config = {}

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('skip')
  end

  it 'omits if no UDAP certifications are supported' do
    config = { udap_certifications_supported: [] }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('omit')
  end

  it 'passes if udap_certifications_required is an array of uri strings' do
    config = { udap_certifications_supported: ['http://abc', 'http://def'],
               udap_certifications_required: ['http://abc', 'http://def'] }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('pass')
  end

  it 'fails if udap_certifications_required is not an array' do
    config = { udap_certifications_supported: ['http://abc', 'http://def'], udap_certifications_required: 'http://abc' }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('fail')
    expect(result.result_message).to match(/be an Array/)
  end

  it 'fails if udap_certifications_required is an array with a non-string element' do
    config = { udap_certifications_supported: ['http://abc', 'http://def'], udap_certifications_required: ['http://abc', 1] }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('fail')
    expect(result.result_message).to match(/Array of strings/)
  end

  it 'fails if udap_certifications_required is an array with a non-uri string element' do
    config = { udap_certifications_supported: ['http://abc', 'http://def'], udap_certifications_required: ['http://abc', 'def'] }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('fail')
    expect(result.result_message).to match(/Array of URI strings/)
  end
end
