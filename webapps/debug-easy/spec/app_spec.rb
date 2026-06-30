require_relative 'spec_helper'

describe 'GET /' do
  it 'returns 200 with TaskAPI in body' do
    get '/'
    expect(last_response.status).to eq(200)
    expect(last_response.body).to include('TaskAPI')
  end
end

describe 'GET /tasks' do
  it 'returns only non-confidential tasks' do
    get '/tasks'
    data = JSON.parse(last_response.body)
    expect(data.length).to eq(2)
    expect(data.none? { |t| t['confidential'] == 1 }).to be true
  end
end

describe 'POST /tasks' do
  it 'creates a task and returns 201' do
    post '/tasks',
         { title: 'New task', details: 'Do it' }.to_json,
         'CONTENT_TYPE' => 'application/json'
    expect(last_response.status).to eq(201)
    expect(JSON.parse(last_response.body)).to have_key('id')
  end
end
