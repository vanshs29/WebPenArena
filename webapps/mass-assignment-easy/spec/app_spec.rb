require_relative 'spec_helper'

describe 'GET /' do
  it 'returns 200 HTML' do
    get '/'
    expect(last_response.status).to eq(200)
    expect(last_response.content_type).to include('text/html')
  end
end

describe 'GET /about' do
  it 'returns 200 HTML' do
    get '/about'
    expect(last_response.status).to eq(200)
    expect(last_response.content_type).to include('text/html')
  end
end

describe 'POST /register' do
  it 'creates a member account regardless of role in the request body' do
    post '/register', { name: 'Alex Chen', email: 'alex@example.com', password: 'secret123', role: 'admin' }.to_json,
         { 'CONTENT_TYPE' => 'application/json' }
    expect(last_response.status).to eq(200)
    data = JSON.parse(last_response.body)
    expect(data['role']).to eq('member')
    expect(data['name']).to eq('Alex Chen')
    expect(data).not_to have_key('password')
    expect(data).not_to have_key('password_hash')
  end

  it 'logs the new user in via session' do
    register(name: 'Alex Chen', email: 'alex@example.com', password: 'secret123')
    get '/profile'
    expect(last_response.status).to eq(200)
  end

  it 'rejects a duplicate email with 409' do
    register(name: 'Alex Chen', email: 'dup@example.com', password: 'secret123')
    register(name: 'Someone Else', email: 'dup@example.com', password: 'other')
    expect(last_response.status).to eq(409)
  end
end

describe 'POST /login' do
  before { register(name: 'Alex Chen', email: 'alex@example.com', password: 'secret123') }

  it 'authenticates with correct credentials' do
    login(email: 'alex@example.com', password: 'secret123')
    expect(last_response.status).to eq(200)
    data = JSON.parse(last_response.body)
    expect(data['email']).to eq('alex@example.com')
  end

  it 'rejects an incorrect password with 401' do
    login(email: 'alex@example.com', password: 'wrong')
    expect(last_response.status).to eq(401)
  end

  it 'rejects an unknown email with 401' do
    login(email: 'nobody@example.com', password: 'secret123')
    expect(last_response.status).to eq(401)
  end
end

describe 'GET /directory' do
  it 'requires authentication' do
    get '/directory'
    expect(last_response.status).to eq(401)
  end

  it 'lists seeded users with name, role, and bio but not email or password' do
    register(name: 'Alex Chen', email: 'alex@example.com', password: 'secret123')
    get '/directory'
    expect(last_response.status).to eq(200)
    data = JSON.parse(last_response.body)
    names = data.map { |u| u['name'] }
    expect(names).to include('Dana Whitfield', 'Sam Okafor', 'Priti Malhotra')
    expect(data.first).not_to have_key('email')
    expect(data.first).not_to have_key('password_hash')
  end
end

describe 'GET /profile' do
  it 'requires authentication' do
    get '/profile'
    expect(last_response.status).to eq(401)
  end

  it "returns the logged-in user's own profile" do
    register(name: 'Alex Chen', email: 'alex@example.com', password: 'secret123')
    get '/profile'
    data = JSON.parse(last_response.body)
    expect(data['name']).to eq('Alex Chen')
    expect(data['role']).to eq('member')
  end
end
