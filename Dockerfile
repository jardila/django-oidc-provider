FROM python:3.6

WORKDIR /srv/app

COPY ./site/requirements.txt ./
COPY ./dist/django-oidc-provider-0.7.1.tar.gz ./django-oidc-provider-0.7.1.tar.gz
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install ./django-oidc-provider-0.7.1.tar.gz

# RUN [ "python", "manage.py", "migrate" ]
# RUN [ "python", "manage.py", "creatersakey" ]

EXPOSE 8000
CMD [ "python", "manage.py", "runserver", "0.0.0.0:8000" ]
