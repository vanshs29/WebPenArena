require 'rack/test'
require 'json'
require_relative '../app'

FIXED_SCORE_TOKEN = 'test-score-token'

def build_app
  Crewsheet.new(database_path: ':memory:', score_token: FIXED_SCORE_TOKEN)
end

RSpec.shared_context 'app' do
  include Rack::Test::Methods

  let(:app) { build_app }

  def register(name:, email:, password:)
    post '/register', { name: name, email: email, password: password }.to_json,
         { 'CONTENT_TYPE' => 'application/json' }
  end

  def login(email:, password:)
    post '/login', { email: email, password: password }.to_json,
         { 'CONTENT_TYPE' => 'application/json' }
  end

  def patch_profile(body)
    patch '/profile', body.to_json, { 'CONTENT_TYPE' => 'application/json' }
  end

  def scores
    get "/score/#{FIXED_SCORE_TOKEN}?format=json"
    JSON.parse(last_response.body)['scores']
  end
end

RSpec.configure do |config|
  config.include_context 'app'
end
