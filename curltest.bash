if ! hash jq 2>/dev/null; then
  echo "The utility jq is required to run this bash script. On mac do 'brew install jq', on ubuntu do 'apt-get install jq'"
  exit 1
fi

if ! hash jsonlint 2>/dev/null; then
  echo "The utility jq is required to run this bash script. On mac do 'npm install jsonlint -g', on ubuntu do 'apt-get install jsonlint'"
  exit 1
fi


echo "POSTing new user"
echo "POST http://localhost:8080/user"
mkfifo curltest_userid
curl "http://localhost:8080/user" -s -X POST -H "Content-Type: application/json" --data "@./testdata/user1_json.json" | jsonlint | tee curltest_userid & \
export CURLTEST_USER_ID=$(jq -r '.result.id' < curltest_userid)
rm curltest_userid

if [ "$CURLTEST_USER_ID" != "null" ]; then
    echo "SUCCESS. Got user-id of $CURLTEST_USER_ID"
else
	exit 1
fi

echo ""
echo "GETing user"
echo "http://localhost:8080/user/$CURLTEST_USER_ID"
curl "http://localhost:8080/user/$CURLTEST_USER_ID" -s | jsonlint

echo ""
echo "PATCHing user"
echo "PATCH http://localhost:8080/user/$CURLTEST_USER_ID"
curl "http://localhost:8080/user/$CURLTEST_USER_ID" -s -X PATCH -H "Content-Type: application/json" --data '{"name": "Hunky Dory"}' | jsonlint

echo ""
echo "DELETE user"
echo "DELETE http://localhost:8080/user/$CURLTEST_USER_ID"
curl "http://localhost:8080/user/$CURLTEST_USER_ID" -s -X DELETE | jsonlint

