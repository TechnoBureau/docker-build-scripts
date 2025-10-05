#!/bin/sh
me="$(basename "$(test -L "$0" && readlink "$0" || echo "$0")")"
RED='\033[0;31m'
NC='\033[0m'
GREEN='\033[0;32m'
RenameFiles() {
find . -name "*$1*" -print0 | while read -d $'\0' file
do
new=`echo $file | sed "s/$1/$2/g"`
echo "Renaming ${RED}$file${NC} \t into \t ${GREEN}$new${NC}"
mv "$file" "$new"
done
}
Replace() {
grep -rl "$1" . | grep -v $me | xargs sed -i '' -e s@"$1"@"$2"@g
}
