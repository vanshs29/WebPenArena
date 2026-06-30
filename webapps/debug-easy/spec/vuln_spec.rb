require_relative 'spec_helper'

describe 'GET /admin/tasks' do
  it 'returns 401 without key' do
    get '/admin/tasks'
    expect(last_response.status).to eq(401)
  end

  it 'returns all 3 tasks with correct key' do
    get '/admin/tasks', {}, { 'HTTP_X_ADMIN_KEY' => FIXED_ADMIN_KEY }
    data = JSON.parse(last_response.body)
    expect(data.length).to eq(3)
    expect(data.any? { |t| t['details'].include?('FLAG{debug_taskapi_easy}') }).to be true
  end

  it 'returns 401 with wrong key' do
    get '/admin/tasks', {}, { 'HTTP_X_ADMIN_KEY' => 'wrong' }
    expect(last_response.status).to eq(401)
  end
end

describe 'GET /debug/env' do
  it 'returns ADMIN_KEY in plaintext' do
    get '/debug/env'
    data = JSON.parse(last_response.body)
    expect(data['ADMIN_KEY']).to eq(FIXED_ADMIN_KEY)
  end

  it 'full chain: debug → key → admin tasks' do
    get '/debug/env'
    key = JSON.parse(last_response.body)['ADMIN_KEY']
    get '/admin/tasks', {}, { 'HTTP_X_ADMIN_KEY' => key }
    expect(last_response.status).to eq(200)
  end
end
