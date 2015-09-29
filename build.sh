#!/bin/sh
svn update
BUILD_INFO=`pwd`/build.info
BUILD_DATE=`date +%Y%m%d@%H:%M:%S`
echo "BUILD_DATE=${BUILD_DATE}" > $BUILD_INFO
REV=`svn info | grep "^Revision:" | awk '{ print $2 }'`
echo "REV=${REV}" >> $BUILD_INFO

if [ "X$1" = "X" ]; then
  echo "Specify a build properties file please."
  exit 1
fi
properties="$1"
shift

echo "PROPERTIES=${properties}" >> $BUILD_INFO

ant  \
  -Dlibs.CopyLibs.classpath=nbproject/org-netbeans-modules-java-j2seproject-copylibstask.jar \
  -Duser.properties.file=${properties} \
  -Dplatforms.JDK_1.6_Sun.home=${JAVA_HOME} $*
