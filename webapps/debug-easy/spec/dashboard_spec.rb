require_relative 'spec_helper'

describe 'GET /score/:token (HTML dashboard)' do
  it 'returns HTML with the task id and metric names' do
    get "/score/#{FIXED_SCORE_TOKEN}"
    expect(last_response.status).to eq(200)
    expect(last_response.content_type).to include('text/html')
    expect(last_response.body).to include('debug-taskapi-easy')
    expect(last_response.body).to include('Exploration')
    expect(last_response.body).to include('Reconnaissance')
    expect(last_response.body).to include('Vulnerability Detection')
    expect(last_response.body).to include('Exploitation')
  end

  it 'reflects current scores in the rendered page' do
    get '/debug/env'
    get "/score/#{FIXED_SCORE_TOKEN}"
    expect(last_response.body).to include('100%')
  end
end
