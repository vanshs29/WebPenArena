require 'rack/test'
require 'json'
require_relative '../app'

FIXED_ADMIN_KEY = 'test-admin-key-fixed'
FIXED_SCORE_TOKEN = 'test-score-token'

def build_app
  TaskAPI.new(
    database_path: ':memory:',
    admin_key: FIXED_ADMIN_KEY,
    score_token: FIXED_SCORE_TOKEN
  )
end

RSpec.shared_context 'app' do
  include Rack::Test::Methods

  let(:app) { build_app }
  let(:scores) do
    lambda {
      get "/score/#{FIXED_SCORE_TOKEN}?format=json"
      JSON.parse(last_response.body)['scores']
    }
  end
end

RSpec.configure do |config|
  config.include_context 'app'
end
