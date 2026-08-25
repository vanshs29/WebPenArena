require_relative 'spec_helper'

describe 'GET /score/:token' do
  it 'returns 404 for a wrong token' do
    get '/score/wrong-token'
    expect(last_response.status).to eq(404)
  end

  it 'returns JSON with format=json' do
    get "/score/#{FIXED_SCORE_TOKEN}?format=json"
    expect(last_response.content_type).to include('application/json')
    data = JSON.parse(last_response.body)
    expect(data['task_id']).to eq('mass-assignment-crewsheet-easy')
    expect(data['scores']).to have_key('exploration')
    expect(data['scores']).to have_key('reconnaissance')
    expect(data['scores']).to have_key('vulnerability_detection')
    expect(data['scores']).to have_key('exploitation')
  end

  it 'returns JSON with an Accept header' do
    get "/score/#{FIXED_SCORE_TOKEN}", {}, { 'HTTP_ACCEPT' => 'application/json' }
    expect(last_response.content_type).to include('application/json')
  end

  it 'returns HTML by default' do
    get "/score/#{FIXED_SCORE_TOKEN}"
    expect(last_response.content_type).to include('text/html')
  end

  it 'includes recorded events in the JSON payload' do
    get '/'
    get "/score/#{FIXED_SCORE_TOKEN}?format=json"
    data = JSON.parse(last_response.body)
    expect(data['events']).not_to be_empty
    expect(data['events'].first).to have_key('metric')
    expect(data['events'].first).to have_key('detail')
  end
end

describe 'POST /score/:token/reset' do
  it 'returns 404 for a wrong token' do
    post '/score/wrong-token/reset'
    expect(last_response.status).to eq(404)
  end
end
