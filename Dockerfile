FROM alpine:3.10

ADD build/main /

RUN mkdir -p /data/buckets
ENV AUTH_KEY="" AUTH_SECRET="" INIT_BUCKET="default" ALLOW_PUBLIC_GET="false"

EXPOSE 9000
CMD /main -backend=fs -fs.path=/data -auth.key=$AUTH_KEY -auth.secret=$AUTH_SECRET -auth.publicget=$ALLOW_PUBLIC_GET -initialbucket=$INIT_BUCKET -debug.host=:8080
