FROM python:3.11
RUN apt-get update --fix-missing && \
    pip3 install requests Flask git+https://github.com/bee-rpc-protocol/celaut-service-libraries
COPY service /service
RUN chmod +x /service/app.py