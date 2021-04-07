FROM alpine
#ENV DEBIAN_FRONTEND noninteractive
# Update
#RUN apt-get update -y \
# && apt-get install -y \
# linux-tool-generic
#  xvfb \
#  npm \
#  wget \
#  && npm install -g n \
#  && n stable

# && PATH="$PATH" \
# && exec bash \
CMD ["/bin/sh"]
