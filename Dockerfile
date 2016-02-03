FROM golang

RUN mkdir /creds
VOLUME /creds

CMD /go-oauth-prov

ADD ./go-oauth-prov /go-oauth-prov
