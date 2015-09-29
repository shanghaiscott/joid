#!/bin/sh
PREFIX=/gm
BUILD_INFO="`pwd`/build.info"
WAR_DIR="${PREFIX}/web/vhost/swdouglass.com/webapps"
NAME="joid-swd"
SWD_WAR="`pwd`/dist/${NAME}.war"
PATCHES="`pwd`/deploy"
PRIVATE="`pwd`/private"

pushd ${WAR_DIR}

if [ -d "$NAME" ]; then
  rm -rf "$NAME"
  rm -f ${PREFIX}/etc/tomcat-vhost/Catalina/swdouglass/${NAME}.xml
fi

mkdir "$NAME" && pushd "$NAME"
  cp $BUILD_INFO .
  jar xf $SWD_WAR
  if [ -d "$PATCHES" ]; then
    for PATCH in $PATCHES/*.patch; do
      patch -p1 < $PATCH
    done
  fi
  if [ -d "$PRIVATE" ]; then
    for PATCH in $PRIVATE/*.patch; do
      patch -p1 < $PATCH
    done
  fi

  chown -R apache:apache .
popd

