RSpec.describe UDAPSecurityTestKit::UDAPTokenUseVerification do # rubocop:disable RSpec/SpecFilePathFormat
  let(:suite_id) { 'udap_security_client' }
  let(:test) { described_class }
  let(:results_repo) { Inferno::Repositories::Results.new }
  let(:dummy_result) { repo_create(:result, test_session_id: test_session.id) }
  let(:access_endpoint) { 'https://inferno.healthit.gov/suites/custom/udap_security_client/fhir/Patient/999' }

  def create_access_request(access_token)
    headers ||= [
      {
        type: 'request',
        name: 'Authorization',
        value: "Bearer #{access_token}"
      }
    ]
    repo_create(
      :request,
      direction: 'incoming',
      url: access_endpoint,
      result: dummy_result,
      test_session_id: test_session.id,
      status: 200,
      tags: [UDAPSecurityTestKit::ACCESS_TAG],
      headers:
    )
  end

  it 'skips if no input tokens' do
    result = run(test)
    expect(result.result).to eq('skip')
    expect(result.result_message).to match(/No token requests made./)
  end

  it 'skips if no access requests' do
    udap_tokens = "abc\n123"
    result = run(test, udap_tokens:)
    expect(result.result).to eq('skip')
    expect(result.result_message).to match(/No successful access requests made./)
  end

  it 'passes an input access token is used in an access request' do
    udap_tokens = "abc\n123"
    create_access_request('123')
    result = run(test, udap_tokens:)
    expect(result.result).to eq('pass')
  end

  it 'fails if no input access token was used on an access request' do
    udap_tokens = "abc\n123"
    create_access_request('xyz')
    result = run(test, udap_tokens:)
    expect(result.result).to eq('fail')
    expect(result.result_message).to match(/Returned tokens never used in any requests./)
  end
end
