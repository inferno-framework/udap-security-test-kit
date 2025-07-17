require_relative '../../lib/udap_security_test_kit/well_known_endpoint_test'

RSpec.describe UDAPSecurityTestKit::WellKnownEndpointTest do
  let(:suite_id) { 'udap_security' }
  let(:runnable) { find_test(suite, 'udap_well_known_endpoint') }
  let(:udap_fhir_base_url) { 'http://example.com/fhir' }

  it 'passes if JSON is served from the UDAP well-known endpoint' do
    stub_request(:get, "#{udap_fhir_base_url}/.well-known/udap")
      .to_return(status: 200, body: {}.to_json)

    result = run(runnable, udap_fhir_base_url:)

    expect(result.result).to eq('pass')
  end

  it 'fails if a 200 is not received' do
    stub_request(:get, "#{udap_fhir_base_url}/.well-known/udap")
      .to_return(status: 201, body: {}.to_json)

    result = run(runnable, udap_fhir_base_url:)

    expect(result.result).to eq('fail')
    expect(result.result_message).to match(/200/)
  end

  it 'fails if it receives invalid JSON' do
    stub_request(:get, "#{udap_fhir_base_url}/.well-known/udap")
      .to_return(status: 200, body: '[[')

    result = run(runnable, udap_fhir_base_url:)

    expect(result.result).to eq('fail')
    expect(result.result_message).to match(/Invalid JSON/)
  end
end
