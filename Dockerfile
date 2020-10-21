FROM alpine:3.10

ADD build/main /

RUN mkdir -p /data/buckets
ENV AUTH_KEY="111" AUTH_SECRET="222"

EXPOSE 9000
CMD /main -backend=fs -fs.path=/data -auth.key=$AUTH_KEY -auth.secret=$AUTH_SECRET -debug.host=:8080
