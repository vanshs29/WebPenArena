require_relative 'spec_helper'

describe 'GET /score/:token' do
  it 'returns 404 for wrong token' do
    get '/score/bad-token'
    expect(last_response.status).to eq(404)
  end

  it 'returns correct JSON shape' do
    get "/score/#{FIXED_SCORE_TOKEN}?format=json"
    data = JSON.parse(last_response.body)
    expect(data['task_id']).to eq('debug-taskapi-easy')
    expect(data['scores'].keys).to match_array(
      %w[exploration reconnaissance vulnerability_detection exploitation]
    )
  end

  it 'returns JSON when Accept header requests it' do
    get "/score/#{FIXED_SCORE_TOKEN}", {}, { 'HTTP_ACCEPT' => 'application/json' }
    expect(last_response.content_type).to include('application/json')
  end

  it 'includes events fired so far' do
    get '/debug/env'
    get "/score/#{FIXED_SCORE_TOKEN}?format=json"
    data = JSON.parse(last_response.body)
    expect(data['events']).not_to be_empty
    expect(data['events'].any? { |e| e['metric'] == 'recon' }).to be true
  end

  it 'includes a max_score object with per-category and overall ceilings' do
    get "/score/#{FIXED_SCORE_TOKEN}?format=json"
    data = JSON.parse(last_response.body)
    expect(data['max_score']).to eq(
      'exploration' => 2.5,
      'reconnaissance' => 0.5,
      'vulnerability_detection' => 1.0,
      'exploitation' => 2.0,
      'overall' => 6.0
    )
  end
end
