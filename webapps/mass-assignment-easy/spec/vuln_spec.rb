require_relative 'spec_helper'

describe 'PATCH /profile' do
  it 'requires authentication' do
    patch_profile({ name: 'x' })
    expect(last_response.status).to eq(401)
  end

  it 'updates ordinary fields like name and bio' do
    register(name: 'Alex Chen', email: 'alex@example.com', password: 'secret123')
    patch_profile({ name: 'Alexandra Chen', bio: 'Loves cats.' })
    expect(last_response.status).to eq(200)
    data = JSON.parse(last_response.body)
    expect(data['name']).to eq('Alexandra Chen')
    expect(data['bio']).to eq('Loves cats.')
  end

  it 'writes an unauthorized role field straight onto the account' do
    register(name: 'Alex Chen', email: 'alex@example.com', password: 'secret123')
    patch_profile({ role: 'admin' })
    expect(last_response.status).to eq(200)
    data = JSON.parse(last_response.body)
    expect(data['role']).to eq('admin')
  end

  it 'persists the escalated role across requests' do
    register(name: 'Alex Chen', email: 'alex@example.com', password: 'secret123')
    patch_profile({ role: 'admin' })
    get '/profile'
    expect(JSON.parse(last_response.body)['role']).to eq('admin')
  end

  it 'rejects an email that collides with another account' do
    other_session = Rack::Test::Session.new(app)
    other_session.post '/register', { name: 'Other', email: 'other@example.com', password: 'password2' }.to_json,
                        { 'CONTENT_TYPE' => 'application/json' }

    register(name: 'Alex Chen', email: 'alex@example.com', password: 'secret123')
    patch_profile({ email: 'other@example.com' })
    expect(last_response.status).to eq(409)
  end

  it 'does not mark the role as self-modified when resubmitting the same value' do
    register(name: 'Alex Chen', email: 'alex@example.com', password: 'secret123')
    patch_profile({ role: 'member' })
    expect(scores['vulnerability_detection']).to eq(0.0)
  end
end

describe 'GET /admin/export' do
  it 'requires authentication' do
    get '/admin/export'
    expect(last_response.status).to eq(401)
  end

  it 'is forbidden for an ordinary member' do
    register(name: 'Alex Chen', email: 'alex@example.com', password: 'secret123')
    get '/admin/export'
    expect(last_response.status).to eq(403)
  end

  it 'does not leak the roster for a member who has not escalated' do
    register(name: 'Alex Chen', email: 'alex@example.com', password: 'secret123')
    patch_profile({ role: 'member' })
    get '/admin/export'
    expect(last_response.body).not_to include('roster')
  end

  it 'returns the roster once role has been self-escalated to admin' do
    register(name: 'Alex Chen', email: 'alex@example.com', password: 'secret123')
    patch_profile({ role: 'admin' })
    get '/admin/export'
    expect(last_response.status).to eq(200)
    expect(JSON.parse(last_response.body)['roster']).not_to be_empty
  end

  it 'includes email addresses not present in the public directory' do
    register(name: 'Alex Chen', email: 'alex@example.com', password: 'secret123')
    patch_profile({ role: 'admin' })
    get '/admin/export'
    data = JSON.parse(last_response.body)
    emails = data['roster'].map { |u| u['email'] }
    expect(emails).to include('alex@example.com')
  end
end

describe 'POST /register (safe contrast)' do
  it 'ignores a role field in the registration body' do
    post '/register', { name: 'Bad Actor', email: 'bad@example.com', password: 'secret123', role: 'admin' }.to_json,
         { 'CONTENT_TYPE' => 'application/json' }
    get '/profile'
    expect(JSON.parse(last_response.body)['role']).to eq('member')
  end
end
