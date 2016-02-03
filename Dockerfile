FROM golang

RUN mkdir /creds
VOLUME /creds

ADD ./go-oauth-prov /go-oauth-prov

ENTRYPOINT /go-oauth-prov
