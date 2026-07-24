FROM php:8.3-cli
WORKDIR /app
COPY . .
ENV SCORE_TOKEN=""
EXPOSE 5000
CMD ["php", "-S", "0.0.0.0:5000", "-t", "public", "router.php"]
