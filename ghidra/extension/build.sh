#!/bin/bash

# config
EXTENSION_NAME='LDGGrep'
EXTENSION_DESCRIPTION="LDGGrep is a path query tool for program analysis."


rp() {
  x=$(readlink -m $1)
  if [ -z "$x" ]; then x=$1;fi
  echo "$x"
}

D="$( cd "$( dirname "$( realpath "${BASH_SOURCE[0]}" )" )" && cd -P "$( dirname "$SOURCE" )" && pwd )"



if [[ "$#" -eq 0 ]]; then
	echo "Usage : $0 <ghidra version> [ghidra distribution]"
	echo
	echo "  where"
	echo "    version is something like 9.2.3 and "
	echo "      distribution is something like PUBLIC"
	exit 1
fi


# set cleanup on script exit
unset tmp_dir
cleanup() {
    if [ ! -z ${tmp_dir+x} ]; then
        echo removing $tmp_dir
        rm -rf "$tmp_dir"
    fi
}
trap cleanup EXIT

GHIDRA_VERSION="$1"
GHIDRA_DISTRIBUTION="${2:-PUBLIC}"

deps_dir=$(realpath "$D/target/dependencies_${GHIDRA_VERSION}")
if [ ! -d "$deps_dir" ]; then
	echo "can't find dependencies dir $deps_dir"
	echo "  build with mvn first.  From root of ldggrep repo:"
	echo "    mvn package -Dghidra.version=$GHIDRA_VERSION"
	exit 1
fi

tmp_dir=`mktemp -d`

# tmp_extension must be absolute
tmp_extension=${tmp_dir}/${EXTENSION_NAME}


mkdir -p ${tmp_extension}/ghidra_scripts
mkdir -p ${tmp_extension}/lib
touch ${tmp_extension}/Module.manifest
cat > ${tmp_extension}/extension.properties <<EOT
name=${EXTENSION_NAME}
description=${EXTENSION_DESCRIPTION}
author=Jason P. Leasure
createdOn=$(date +%m/%d/%Y)
version=${GHIDRA_VERSION}
EOT

cp -r "$D/data" ${tmp_extension}/
cp -r "$D/ghidra_scripts" ${tmp_extension}/

cp -f ${deps_dir}/* ${tmp_extension}/lib

echo remove module-info from jars in lib
for x in ${tmp_extension}/lib/*.jar; do
	zip -qd $x ./module-info.class ./module-info.java 2>/dev/null 1>&2 || true
done

# ZIPNAME=ghidra_${GHIDRA_VERSION}_${GHIDRA_DISTRIBUTION}_`date +'%Y%m%d'`_${EXTENSION_NAME,,}.zip
ZIPNAME=ghidra_${GHIDRA_VERSION}_${GHIDRA_DISTRIBUTION}_`date +'%Y%m%d'`_${EXTENSION_NAME}.zip
rm -f "${ZIPNAME}"
( cd "$tmp_dir" && zip -r "${D}/target/${ZIPNAME}" "${EXTENSION_NAME}" )

