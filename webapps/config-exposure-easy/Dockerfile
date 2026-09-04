FROM php:8.3-cli
WORKDIR /app
COPY bootstrap.php config.php router.php ./
COPY src/ ./src/
COPY templates/ ./templates/
COPY public/ ./public/
ENV SCORE_TOKEN=""
EXPOSE 5000
CMD ["php", "-S", "0.0.0.0:5000", "-t", "public", "router.php"]
