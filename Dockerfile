FROM python:3-alpine

# Keeps Python from generating .pyc files in the container
ENV PYTHONDONTWRITEBYTECODE=1

# Turns off buffering for easier container logging
ENV PYTHONUNBUFFERED=1

# Turn off PIP warnings
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
ENV PIP_ROOT_USER_ACTION=ignore

# Install pip requirements
COPY . /app
RUN apk add --update --no-cache shadow && \
    rm -rf /var/cache/apk/* && \
    python3 -m pip install -r /app/requirements.txt

WORKDIR /app

# Creates a non-root user with an explicit UID and adds permission to access the /app folder
RUN adduser -u 5678 --disabled-password --gecos "Tokendito" -h /app -H tokendito && \
    chown -R tokendito:tokendito /app

USER tokendito

ENTRYPOINT ["python3", "tokendito/tokendito.py"]
