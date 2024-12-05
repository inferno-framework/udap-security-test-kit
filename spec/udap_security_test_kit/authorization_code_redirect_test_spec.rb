require_relative '../../lib/udap_security_test_kit/authorization_code_redirect_test'

RSpec.describe UDAPSecurityTestKit::AuthorizationCodeRedirectTest, :redirect do
  include Rack::Test::Methods

  let(:test) { Inferno::Repositories::Tests.new.find('udap_authorization_code_redirect') }
  let(:session_data_repo) { Inferno::Repositories::SessionData.new }
  let(:results_repo) { Inferno::Repositories::Results.new }
  let(:requests_repo) { Inferno::Repositories::Requests.new }
  let(:test_session) { repo_create(:test_session, test_suite_id: 'udap_security') }
  let(:url) { 'http://example.com/fhir' }
  let(:inputs) do
    {
      udap_authorization_endpoint: 'http://example.com/authorize',
      udap_client_id: 'CLIENT_ID'
    }
  end

  def app
    Inferno::Web.app
  end

  def run(runnable, inputs = {})
    test_run_params = { test_session_id: test_session.id }.merge(runnable.reference_hash)
    test_run = Inferno::Repositories::TestRuns.new.create(test_run_params)
    inputs.each do |name, value|
      type = runnable.config.input_type(name)
      type = 'text' if type == 'radio'
      session_data_repo.save(
        test_session_id: test_session.id,
        name:,
        value:,
        type:
      )
    end
    Inferno::TestRunner.new(test_session:, test_run:).run(runnable)
  end

  it 'waits and then passes when it receives a request with the correct state' do
    allow(test).to receive(:parent).and_return(Inferno::TestGroup)
    result = run(test, inputs)
    expect(result.result).to eq('wait')

    state = session_data_repo.load(test_session_id: test_session.id, name: 'udap_authorization_code_state')
    get "/custom/udap_security/redirect?state=#{state}"

    result = results_repo.find(result.id)
    expect(result.result).to eq('pass')
  end

  it 'continues to wait when it receives a request with the incorrect state' do
    result = run(test, inputs)
    expect(result.result).to eq('wait')

    state = SecureRandom.uuid
    get "/custom/smart/redirect?state=#{state}"

    result = results_repo.find(result.id)
    expect(result.result).to eq('wait')
  end

  it 'fails if the authorization url is invalid' do
    inputs[:udap_authorization_endpoint] = 'invalid'
    result = run(test, inputs)
    expect(result.result).to eq('fail')
    expect(result.result_message).to match(/is not a valid URI/)
  end

  it "persists the incoming 'redirect' request" do
    allow(test).to receive(:parent).and_return(Inferno::TestGroup)
    run(test, inputs)
    state = session_data_repo.load(test_session_id: test_session.id, name: 'udap_authorization_code_state')
    url = "/custom/udap_security/redirect?state=#{state}"
    get url

    request = requests_repo.find_named_request(test_session.id, 'redirect')
    expect(request.url).to end_with(url)
  end

  it "persists the 'udap_authorization_code_state' output" do
    result = run(test, inputs)
    expect(result.result).to eq('wait')

    state = result.result_message.match(/a state of `(.*)`/)[1]
    persisted_state = session_data_repo.load(test_session_id: test_session.id, name: 'udap_authorization_code_state')

    expect(persisted_state).to eq(state)
  end
end
