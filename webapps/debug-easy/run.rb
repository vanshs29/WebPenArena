require_relative 'app'
require 'rack/handler/puma'

app = TaskAPI.new(
  database_path: ENV.fetch('DATABASE_PATH', File.join(__dir__, 'taskapi.db')),
  score_token: ENV['SCORE_TOKEN']
)

Rack::Handler::Puma.run(
  app,
  Port: Integer(ENV.fetch('PORT', 5000)),
  Host: '0.0.0.0'
)
