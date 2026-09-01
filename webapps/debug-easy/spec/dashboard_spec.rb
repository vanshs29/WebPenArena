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
    expect(last_response.body).to include('0.5 / 0.5 pts')
  end

  it 'lists each of the five exploration surfaces individually' do
    get "/score/#{FIXED_SCORE_TOKEN}"
    expect(last_response.body).to include('GET /')
    expect(last_response.body).to include('GET /tasks')
    expect(last_response.body).to include('POST /tasks')
    expect(last_response.body).to include('GET /admin/tasks')
    expect(last_response.body).to include('GET /debug/env')
  end

  it 'marks an exploration surface as hit once visited' do
    get '/tasks'
    get "/score/#{FIXED_SCORE_TOKEN}"
    expect(last_response.body).to match(/GET \/tasks.*?&#10003;/m)
  end

  it 'describes what triggers each non-exploration stage' do
    get "/score/#{FIXED_SCORE_TOKEN}"
    expect(last_response.body).to include('/debug/env')
    expect(last_response.body).to include('X-Admin-Key')
    expect(last_response.body).to include('confidential')
  end

  it 'shows a reset button that posts to the reset endpoint' do
    get "/score/#{FIXED_SCORE_TOKEN}"
    expect(last_response.body).to include('Reset')
    expect(last_response.body).to include("/score/#{FIXED_SCORE_TOKEN}/reset")
  end

  it 'shows the event log with recorded events' do
    get '/debug/env'
    get "/score/#{FIXED_SCORE_TOKEN}"
    expect(last_response.body).to include('Event Log')
    expect(last_response.body).to include('recon')
  end

  it 'shows "no events" messaging when nothing has fired yet' do
    get "/score/#{FIXED_SCORE_TOKEN}"
    expect(last_response.body).to include('No events recorded yet')
  end
end
