require_relative 'spec_helper'

describe 'POST /score/:token/reset' do
  it 'returns 404 for wrong token' do
    post '/score/bad-token/reset'
    expect(last_response.status).to eq(404)
  end

  it 'clears all scoring events' do
    get '/debug/env'
    get '/admin/tasks', {}, { 'HTTP_X_ADMIN_KEY' => FIXED_ADMIN_KEY }
    post "/score/#{FIXED_SCORE_TOKEN}/reset"
    expect(scores.call.values.all? { |v| v == 0.0 }).to be true
  end

  it 'rotates the admin key' do
    old_key = FIXED_ADMIN_KEY
    post "/score/#{FIXED_SCORE_TOKEN}/reset"
    get '/debug/env'
    new_key = JSON.parse(last_response.body)['ADMIN_KEY']
    expect(new_key).not_to eq(old_key)
  end

  it 'returns a reset status payload' do
    post "/score/#{FIXED_SCORE_TOKEN}/reset"
    data = JSON.parse(last_response.body)
    expect(data['status']).to eq('reset')
    expect(data).to have_key('new_task_start')
  end

  it 're-seeds exactly the original 3 tasks' do
    post '/tasks', { title: 'extra', details: '' }.to_json, 'CONTENT_TYPE' => 'application/json'
    post "/score/#{FIXED_SCORE_TOKEN}/reset"
    get '/debug/env'
    new_key = JSON.parse(last_response.body)['ADMIN_KEY']
    get '/admin/tasks', {}, { 'HTTP_X_ADMIN_KEY' => new_key }
    data = JSON.parse(last_response.body)
    expect(data.length).to eq(3)
  end
end
