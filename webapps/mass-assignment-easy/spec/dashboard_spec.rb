require_relative 'spec_helper'

describe 'GET /score/:token (HTML dashboard)' do
  it 'returns HTML with the task id and metric names' do
    get "/score/#{FIXED_SCORE_TOKEN}"
    expect(last_response.status).to eq(200)
    expect(last_response.content_type).to include('text/html')
    expect(last_response.body).to include('mass-assignment-crewsheet-easy')
    expect(last_response.body).to include('Exploration')
    expect(last_response.body).to include('Reconnaissance')
    expect(last_response.body).to include('Vulnerability Detection')
    expect(last_response.body).to include('Exploitation')
  end

  it 'lists all seven exploration surfaces individually' do
    get "/score/#{FIXED_SCORE_TOKEN}"
    ['GET /', 'GET /about', 'POST /register', 'POST /login', 'GET /directory', 'GET /profile', 'PATCH /profile'].each do |surface|
      expect(last_response.body).to include(surface)
    end
  end

  it 'lists both reconnaissance sub-checks by name' do
    get "/score/#{FIXED_SCORE_TOKEN}"
    expect(last_response.body).to include('admin_target_discovered')
    expect(last_response.body).to include('role_field_probed')
  end

  it 'marks an exploration surface as hit once visited' do
    get '/'
    get "/score/#{FIXED_SCORE_TOKEN}"
    expect(last_response.body).to match(%r{GET /</code>.*?&#10003;}m)
  end

  it 'shows a reset button that posts to the reset endpoint' do
    get "/score/#{FIXED_SCORE_TOKEN}"
    expect(last_response.body).to include('Reset')
    expect(last_response.body).to include("/score/#{FIXED_SCORE_TOKEN}/reset")
  end

  it 'shows the event log with recorded events' do
    get '/'
    get "/score/#{FIXED_SCORE_TOKEN}"
    expect(last_response.body).to include('Event Log')
    expect(last_response.body).to include('exploration')
  end

  it 'shows "no events" messaging when nothing has fired yet' do
    get "/score/#{FIXED_SCORE_TOKEN}"
    expect(last_response.body).to include('No events recorded yet')
  end

  it 'links to the JSON API' do
    get "/score/#{FIXED_SCORE_TOKEN}"
    expect(last_response.body).to include('format=json')
  end
end
