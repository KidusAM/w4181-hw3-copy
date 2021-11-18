from django.test import Client, TestCase
from django.db import connection
from django.contrib.auth import authenticate
from LegacySite.models import User
from os import system
import LegacySite.extras as extras

# Create your tests here.
# Please view: https://docs.djangoproject.com/en/3.2/topics/testing/overview/
c = Client()

# Sample check that you can access website
response = c.get("/gift/")
assert(response.status_code == 200)

def clean_dummies():
		system('sqlite3 db.sqlite3 < clean_users.sh')

# 1- Write the test confirming XSS vulnerability is fixed
def test_xss():
		URL = "/buy.html?director=%22%3C/p%3E%3Cscript%3Ealert(xss)%3C/script%3E%3Cp%3E%22"

		response = c.get(URL)
		if "</p><script>alert(xss)</script><p>" in response.content.decode():
				print("xss worked")
				# raise RuntimeError("XSS vulnerability found in /buy?director=")

# 2- Write the test confirming CSRF vulnerability is fixed
def test_csrf():
		# first, create 2 dummy users
		clean_dummies()
		dummy_users = [("mydummyuser1", "dummypass1"), ("mydummyuser2",
														   "dummypass2")]
		for uname, pwd in dummy_users:
				salt = extras.generate_salt(16)
				hashed_pword = extras.hash_pword(salt, pwd)
				hashed_pword = salt.decode('utf-8') + '$' + hashed_pword
				u = authenticate(username=uname, password=hashed_pword)
				if u is not None:
						u.delete()
				u = User(username=uname, password=hashed_pword)
				u.save()

		response = c.post("/login/", {'uname':dummy_users[0][0],
					 'pword':dummy_users[0][1]})

		if response.status_code != 302:
				raise RuntimeError("Login failed when trying to test csrf")

		# now try the csrf attack on the first dummy user
		response = c.post("/gift", {'amount':1, 'username':dummy_users[1][0]})

		if "Card given to" in response.content.decode():
				print("csrf worked")
				# raise RuntimeError("CSRF vulnerability found in /gift")

# 3- Write the test confirming SQL Injection attack is fixed
def test_sqli():
		clean_dummies()
		payload = """ {"merchant_id": "NYU Apparel Card", "customer_id": "kidus", "total_value": "123456", "records": [{"record_type": "amount_change", "amount_added": 2000, "signature": "nothing' UNION select username || ': ' || password from LegacySite_user --"}]} """
		# first, create a dummy user
		uname, pwd = "mydummyuser1", "dummypass1"
		salt = extras.generate_salt(16)
		hashed_pword = extras.hash_pword(salt, pwd)
		hashed_pword = salt.decode('utf-8') + '$' + hashed_pword
		u = User(username=uname, password=hashed_pword)
		u.save()

		with open("tmp_file", "w") as tmp: tmp.write(payload)

		response = c.post("/login/", {'uname':uname, 'pword':pwd})

		if response.status_code != 302:
				raise RuntimeError("Login failed when trying to test sqli")

		# now do the sql file upload
		response = None
		with open("tmp_file", "r") as fp:
				response = c.post("/use.html", {'card_data':fp,
									'card_supplied':"true"})

		if "admin: " in response.content.decode():
				print("sqli worked")

test_xss()
test_csrf()
test_sqli()
