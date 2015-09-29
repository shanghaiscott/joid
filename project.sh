#!/bin/sh
# build a tarball of the whole project
NAME="joid"

# cleanup
ANTOPTS=
if [ "X$1" != "X" ]; then
  ANTOPTS="-Dlibs.CopyLibs.classpath=nbproject/org-netbeans-modules-java-j2seproject-copylibstask.jar -Duser.properties.file=${1} -Dplatforms.JDK_1.6_Sun.home=${JAVA_HOME}"
fi
ant $ANTOPTS  clean

# export from svn
REV="`svn info |grep Revision | awk '{ print $2 }'`"
PROJECT="joid"
VENDOR="swd"
DIST="${PROJECT}-${VENDOR}-svn${REV}"

pushd ..
  /bin/rm -rf ${DIST}
  svn export ${NAME} ${DIST}
  tar zcf ../dist/${DIST}.tar.gz ${DIST}
  sha256sum ../dist/${DIST}.tar.gz > ../dist/${DIST}.tar.gz.sha256
popd
