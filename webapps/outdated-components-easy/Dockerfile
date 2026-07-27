FROM python:3.12-slim AS imagemagick-build

# ImageMagick 6.9.3-9 (29 Apr 2016) -- the release immediately before the
# ImageTragick (CVE-2016-3714) fix landed in 6.9.3-10. Fetched by commit SHA
# from the ImageMagick6 mirror since upstream tags only go back to 6.9.4-0.
ARG IMAGEMAGICK_COMMIT=2458872ae906063029ed413f77946791cc20b64e

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential wget pkg-config \
    libpng-dev libjpeg62-turbo-dev libxml2-dev libbz2-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN wget -q -O im-src.tar.gz \
      "https://github.com/ImageMagick/ImageMagick6/archive/${IMAGEMAGICK_COMMIT}.tar.gz" \
    && tar xzf im-src.tar.gz \
    && mv ImageMagick6-${IMAGEMAGICK_COMMIT} im-src

WORKDIR /build/im-src
RUN ./configure --without-magick-plus-plus --disable-static --without-modules \
    && make -j"$(nproc)" \
    && make install \
    && ldconfig

# Verify this is genuinely the pre-patch, RCE-capable build before shipping it.
RUN convert -version | grep -q "6.9.3-9"
RUN printf "push graphic-context\nviewbox 0 0 640 480\nimage over 0,0 0,0 '|touch /tmp/build_verify_proof'\npop graphic-context\n" > /tmp/verify.png \
    && (convert /tmp/verify.png /tmp/verify_out.png || true) \
    && test -f /tmp/build_verify_proof \
    && rm -f /tmp/build_verify_proof /tmp/verify.png /tmp/verify_out.png


FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpng16-16 libjpeg62-turbo libxml2 libbz2-1.0 libgomp1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=imagemagick-build /usr/local/bin/convert /usr/local/bin/convert
COPY --from=imagemagick-build /usr/local/bin/identify /usr/local/bin/identify
COPY --from=imagemagick-build /usr/local/lib/libMagick*.so* /usr/local/lib/
COPY --from=imagemagick-build /usr/local/etc/ImageMagick-6/ /usr/local/etc/ImageMagick-6/
RUN ldconfig

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ ./app/
COPY run.py ./

ENV SCORE_TOKEN=""
EXPOSE 5000
CMD ["python", "run.py"]
