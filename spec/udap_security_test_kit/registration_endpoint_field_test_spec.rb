require_relative '../../lib/udap_security_test_kit/registration_endpoint_field_test'

RSpec.describe UDAPSecurityTestKit::RegistrationEndpointFieldTest do
  let(:suite_id) { 'udap_security' }
  let(:runnable) { find_test(suite, 'udap_registration_endpoint_field') }

  it 'fails if field is not present' do
    config = {}

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('fail')
  end

  it 'passes if registration_endpoint is a uri string' do
    config = { registration_endpoint: 'http://abc' }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('pass')
  end

  it 'fails if registration_endpoint is not a string' do
    config = { registration_endpoint: ['http://abc'] }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('fail')
    expect(result.result_message).to match(/be a String/)
  end

  it 'fails if registration_endpoint is a non-uri string' do
    config = { registration_endpoint: 'def' }

    result = run(runnable, udap_well_known_metadata_json: config.to_json)

    expect(result.result).to eq('fail')
    expect(result.result_message).to match(/valid URI/)
  end
end
