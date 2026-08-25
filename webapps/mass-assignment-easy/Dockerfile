FROM ruby:3.3-slim

RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    build-essential \
    libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Gemfile Gemfile.lock ./
RUN bundle config set --local without 'test' && bundle install

COPY app.rb run.rb ./
COPY views/ ./views/

ENV SCORE_TOKEN=""
ENV PORT=5000
EXPOSE 5000
CMD ["ruby", "run.rb"]
